from datetime import timedelta
import csv
from pathlib import Path
from django.shortcuts import render, get_object_or_404, redirect
from django.http import JsonResponse, HttpResponse, StreamingHttpResponse
from django.db import models
from django.utils import timezone
from django.conf import settings
from django.db.models.functions import TruncMinute
from django.db.models import Q
from django.core.paginator import Paginator
from .models import PacketLog, SecurityAlert, DetectionSetting, MonitoringSession
from .services import get_sniffer
from .utils import list_interfaces
from .detectors import get_config


def dashboard(request):
    total_packets = PacketLog.objects.count()
    total_tcp = PacketLog.objects.filter(protocol="TCP").count()
    total_alerts = SecurityAlert.objects.count()
    alerts_by_type = (
        SecurityAlert.objects.values("alert_type").order_by().annotate(count=models.Count("id"))
    )
    severity_counts = (
        SecurityAlert.objects.values("severity").order_by().annotate(count=models.Count("id"))
    )
    top_ips = (
        SecurityAlert.objects.values("src_ip").exclude(src_ip=None)
        .order_by()
        .annotate(count=models.Count("id"))
        .order_by("-count")[:5]
    )
    top_ports = (
        PacketLog.objects.values("dst_port")
        .annotate(count=models.Count("id"))
        .order_by("-count")[:8]
    )
    # Packet rate (last 10 minutes)
    ten_min_ago = timezone.now() - timedelta(minutes=10)
    packet_rate = (
        PacketLog.objects.filter(timestamp__gte=ten_min_ago)
        .annotate(minute=TruncMinute("timestamp"))
        .values("minute")
        .annotate(count=models.Count("id"))
        .order_by("minute")
    )
    # Flag distribution (last 500 packets)
    flag_counts = {"S": 0, "A": 0, "R": 0, "F": 0}
    for p in PacketLog.objects.order_by("-timestamp")[:500]:
        for f in flag_counts.keys():
            if f in p.flags:
                flag_counts[f] += 1
    recent_alerts = SecurityAlert.objects.all()[:10]
    return render(
        request,
        "monitor/dashboard.html",
        {
            "total_packets": total_packets,
            "total_tcp": total_tcp,
            "total_alerts": total_alerts,
            "alerts_by_type": alerts_by_type,
            "severity_counts": severity_counts,
            "top_ips": top_ips,
            "top_ports": top_ports,
            "packet_rate": packet_rate,
            "flag_counts": flag_counts,
            "recent_alerts": recent_alerts,
        },
    )


def alerts(request):
    qs = SecurityAlert.objects.all()
    per_page_choices = [10, 25, 50, 100, 200]
    search = request.GET.get("q", "").strip()
    if search:
        qs = qs.filter(
            Q(alert_type__icontains=search)
            | Q(severity__icontains=search)
            | Q(src_ip__icontains=search)
            | Q(dst_ip__icontains=search)
            | Q(description__icontains=search)
        )
    sort = request.GET.get("sort", "-created_at")
    allowed_sorts = {
        "time": "created_at",
        "-time": "-created_at",
        "type": "alert_type",
        "-type": "-alert_type",
        "severity": "severity",
        "-severity": "-severity",
    }
    qs = qs.order_by(allowed_sorts.get(sort, "-created_at"))
    try:
        per_page = int(request.GET.get("per_page", 10))
    except (TypeError, ValueError):
        per_page = 10
    per_page = max(5, min(per_page, 200))
    paginator = Paginator(qs, per_page)
    page_obj = paginator.get_page(request.GET.get("page"))
    return render(
        request,
        "monitor/alerts.html",
        {
            "alerts": page_obj,
            "search": search,
            "sort": sort,
            "per_page": per_page,
            "per_page_choices": per_page_choices,
        },
    )


def export_alerts_csv(request):
    class Echo:
        def write(self, value):
            return value

    pseudo_buffer = Echo()
    writer = csv.writer(pseudo_buffer)

    def row_iter():
        yield writer.writerow(["timestamp", "type", "severity", "src_ip", "dst_ip", "description"])
        for a in SecurityAlert.objects.all().order_by("-created_at").iterator(chunk_size=500):
            yield writer.writerow([a.created_at, a.alert_type, a.severity, a.src_ip, a.dst_ip, a.description])

    response = StreamingHttpResponse(row_iter(), content_type="text/csv")
    response["Content-Disposition"] = "attachment; filename=alerts.csv"
    return response


def alert_detail(request, pk):
    alert = get_object_or_404(SecurityAlert, pk=pk)
    return render(request, "monitor/alert_detail.html", {"alert": alert})


def traffic(request):
    qs = PacketLog.objects.all()
    per_page_choices = [10, 25, 50, 100, 200]
    search = request.GET.get("q", "").strip()
    flow = request.GET.get("flow", "").strip()
    if search:
        qs = qs.filter(
            Q(src_ip__icontains=search)
            | Q(dst_ip__icontains=search)
            | Q(flags__icontains=search)
        )
    if flow and "->" in flow:
        try:
            left, right = flow.split("->", 1)
            src_ip, src_port = left.rsplit(":", 1)
            dst_ip, dst_port = right.rsplit(":", 1)
            qs = qs.filter(src_ip=src_ip, src_port=int(src_port), dst_ip=dst_ip, dst_port=int(dst_port))
        except Exception:
            pass
    sort = request.GET.get("sort", "-timestamp")
    allowed_sorts = {
        "time": "timestamp",
        "-time": "-timestamp",
        "src": "src_ip",
        "-src": "-src_ip",
        "dst": "dst_ip",
        "-dst": "-dst_ip",
        "len": "length",
        "-len": "-length",
    }
    qs = qs.order_by(allowed_sorts.get(sort, "-timestamp"))
    try:
        per_page = int(request.GET.get("per_page", 10))
    except (TypeError, ValueError):
        per_page = 10
    per_page = max(5, min(per_page, 200))
    paginator = Paginator(qs, per_page)
    page_obj = paginator.get_page(request.GET.get("page"))
    return render(
        request,
        "monitor/traffic.html",
        {
            "packets": page_obj,
            "search": search,
            "flow": flow,
            "sort": sort,
            "per_page": per_page,
            "per_page_choices": per_page_choices,
        },
    )


def session_detail(request, pk):
    session = get_object_or_404(MonitoringSession, pk=pk)
    start = session.started_at
    end = session.ended_at or timezone.now()

    alerts_qs = SecurityAlert.objects.filter(created_at__gte=start, created_at__lte=end)
    packets_qs = PacketLog.objects.filter(timestamp__gte=start, timestamp__lte=end)

    # CSV export for alerts in this session
    if request.GET.get("csv") == "alerts":
        class Echo:
            def write(self, value):
                return value

        pseudo_buffer = Echo()
        writer = csv.writer(pseudo_buffer)

        def row_iter():
            yield writer.writerow(["timestamp", "type", "severity", "src_ip", "dst_ip", "description"])
            for a in alerts_qs.order_by("-created_at").iterator(chunk_size=500):
                yield writer.writerow([a.created_at, a.alert_type, a.severity, a.src_ip, a.dst_ip, a.description])

        response = StreamingHttpResponse(row_iter(), content_type="text/csv")
        response["Content-Disposition"] = f'attachment; filename="session_{pk}_alerts.csv"'
        return response

    per_page_alerts_choices = [10, 25, 50, 100, 200]
    per_page_packets_choices = [10, 25, 50, 100, 200]

    try:
        per_page_alerts = int(request.GET.get("per_page_alerts", 10))
    except (TypeError, ValueError):
        per_page_alerts = 10
    per_page_alerts = max(5, min(per_page_alerts, 200))

    try:
        per_page_packets = int(request.GET.get("per_page_packets", 10))
    except (TypeError, ValueError):
        per_page_packets = 10
    per_page_packets = max(5, min(per_page_packets, 200))

    alerts_page = Paginator(alerts_qs.order_by("-created_at"), per_page_alerts).get_page(
        request.GET.get("a_page")
    )
    packets_page = Paginator(packets_qs.order_by("-timestamp"), per_page_packets).get_page(
        request.GET.get("p_page")
    )

    return render(
        request,
        "monitor/session_detail.html",
        {
            "session": session,
            "alerts": alerts_page,
            "packets": packets_page,
            "per_page_alerts": per_page_alerts,
            "per_page_packets": per_page_packets,
            "per_page_alerts_choices": per_page_alerts_choices,
            "per_page_packets_choices": per_page_packets_choices,
        },
    )


def monitoring(request):
    sniffer = get_sniffer()
    active = sniffer.is_running()
    sessions = MonitoringSession.objects.order_by("-started_at")[:20]
    return render(
        request,
        "monitor/monitoring.html",
        {
            "active": active,
            "interface": sniffer.interface,
            "sessions": sessions,
            "interfaces": list_interfaces(),
        },
    )


def upload_pcap(request):
    if request.method == "POST" and request.FILES.get("pcap"):
        pcap_file = request.FILES["pcap"]
        pcap_dir = Path(settings.BASE_DIR) / "pcaps"
        pcap_dir.mkdir(exist_ok=True)
        save_path = pcap_dir / pcap_file.name
        with open(save_path, "wb+") as dest:
            for chunk in pcap_file.chunks():
                dest.write(chunk)
        sniffer = get_sniffer()
        sniffer.stop()
        sniffer.process_pcap(save_path)
        return redirect("monitoring")
    return redirect("monitoring")


def about(request):
    return render(request, "monitor/about.html")


def settings_view(request):
    ds, _ = DetectionSetting.objects.get_or_create(id=1)
    if request.method == "POST":
        for field in [
            "syn_threshold",
            "syn_window_seconds",
            "handshake_completion_min_ratio",
            "rst_threshold",
            "rst_window_seconds",
            "hijack_seq_jump",
            "alert_cooldown_seconds",
            "port_scan_port_threshold",
            "port_scan_window",
        ]:
            val = request.POST.get(field)
            if val is not None:
                if "ratio" in field:
                    setattr(ds, field, float(val))
                else:
                    setattr(ds, field, int(val))
        ds.save()
        return redirect("/settings/?saved=1")
    return render(request, "monitor/settings.html", {"settings": ds, "interfaces": list_interfaces()})


def start_sniff(request):
    iface = request.GET.get("iface")
    sniffer = get_sniffer()
    if not iface:
        return JsonResponse({"status": "error", "message": "Interface required"}, status=400)
    try:
        sniffer.start(iface)
    except Exception as exc:
        return JsonResponse({"status": "error", "message": str(exc)}, status=500)
    return JsonResponse({"status": "started", "iface": iface, "active": sniffer.is_running()})


def stop_sniff(request):
    sniffer = get_sniffer()
    err = sniffer.stop()
    if err:
        # Still report stopped state but include message for UI
        return JsonResponse({"status": "stopped_with_error", "message": err, "active": sniffer.is_running(), "iface": sniffer.interface}, status=200)
    return JsonResponse({"status": "stopped", "active": sniffer.is_running(), "iface": sniffer.interface})


def stop_all_sessions(request):
    """
    Stop the sniffer and mark any active MonitoringSession rows as closed.
    Useful when a sniffer thread crashed or the page was refreshed while running.
    """
    sniffer = get_sniffer()
    err = sniffer.stop()
    now = timezone.now()
    MonitoringSession.objects.filter(is_active=True).update(is_active=False, ended_at=now)
    return JsonResponse({"status": "stopped_all", "message": err, "active": sniffer.is_running(), "iface": sniffer.interface})


def status(request):
    sniffer = get_sniffer()
    active = sniffer.is_running()
    session_data = {}
    try:
        if getattr(sniffer, "session", None):
            sess = (
                MonitoringSession.objects.filter(pk=sniffer.session.pk)
                .values("id", "packet_count", "alert_count")
                .first()
            )
            if sess:
                session_data = {
                    "session_id": sess["id"],
                    "packet_count": sess["packet_count"],
                    "alert_count": sess["alert_count"],
                }
    except Exception:
        # Fail soft; still return active state
        session_data = {}
    return JsonResponse(
        {
            "active": active,
            "interface": sniffer.interface,
            **session_data,
        }
    )


def interfaces(request):
    return JsonResponse({"interfaces": list_interfaces()})


def rules(request):
    # pull current detection config; fall back to defaults inside get_config
    cfg = get_config()
    return render(request, "monitor/rules.html", {"cfg": cfg})
