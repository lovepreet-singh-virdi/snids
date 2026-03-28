from datetime import timedelta
import csv
from pathlib import Path
from django.shortcuts import render, get_object_or_404, redirect
from django.http import JsonResponse, HttpResponse
from django.db import models
from django.utils import timezone
from django.conf import settings
from django.db.models.functions import TruncMinute
from .models import PacketLog, SecurityAlert, DetectionSetting, MonitoringSession
from .services import get_sniffer
from .utils import list_interfaces


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
            "packet_rate": packet_rate,
            "flag_counts": flag_counts,
            "recent_alerts": recent_alerts,
        },
    )


def alerts(request):
    data = SecurityAlert.objects.all()
    return render(request, "monitor/alerts.html", {"alerts": data})


def export_alerts_csv(request):
    response = HttpResponse(content_type="text/csv")
    response["Content-Disposition"] = "attachment; filename=alerts.csv"
    writer = csv.writer(response)
    writer.writerow(["timestamp", "type", "severity", "src_ip", "dst_ip", "description"])
    for a in SecurityAlert.objects.all().order_by("-created_at"):
        writer.writerow([a.created_at, a.alert_type, a.severity, a.src_ip, a.dst_ip, a.description])
    return response


def alert_detail(request, pk):
    alert = get_object_or_404(SecurityAlert, pk=pk)
    return render(request, "monitor/alert_detail.html", {"alert": alert})


def traffic(request):
    packets = PacketLog.objects.order_by("-timestamp")[:200]
    return render(request, "monitor/traffic.html", {"packets": packets})


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
        ]:
            val = request.POST.get(field)
            if val is not None:
                if "ratio" in field:
                    setattr(ds, field, float(val))
                else:
                    setattr(ds, field, int(val))
        ds.save()
        return redirect("settings")
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
    return JsonResponse({"status": "started", "iface": iface})


def stop_sniff(request):
    sniffer = get_sniffer()
    sniffer.stop()
    return JsonResponse({"status": "stopped"})


def status(request):
    sniffer = get_sniffer()
    active = sniffer.is_running()
    return JsonResponse({"active": active, "interface": sniffer.interface})


def interfaces(request):
    return JsonResponse({"interfaces": list_interfaces()})