from django.shortcuts import render, get_object_or_404, redirect
from django.http import JsonResponse
from django.db import models
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
    recent_alerts = SecurityAlert.objects.all()[:10]
    return render(
        request,
        "monitor/dashboard.html",
        {
            "total_packets": total_packets,
            "total_tcp": total_tcp,
            "total_alerts": total_alerts,
            "alerts_by_type": alerts_by_type,
            "recent_alerts": recent_alerts,
        },
    )


def alerts(request):
    data = SecurityAlert.objects.all()
    return render(request, "monitor/alerts.html", {"alerts": data})


def alert_detail(request, pk):
    alert = get_object_or_404(SecurityAlert, pk=pk)
    return render(request, "monitor/alert_detail.html", {"alert": alert})


def traffic(request):
    packets = PacketLog.objects.order_by("-timestamp")[:200]
    return render(request, "monitor/traffic.html", {"packets": packets})


def monitoring(request):
    sniffer = get_sniffer()
    active = sniffer.thread.is_alive() if sniffer.thread else False
    sessions = MonitoringSession.objects.order_by("-started_at")[:20]
    return render(
        request,
        "monitor/monitoring.html",
        {
            "active": active,
            "interface": sniffer.interface,
            "sessions": sessions,
        },
    )


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
    return render(request, "monitor/settings.html", {"settings": ds})


def start_sniff(request):
    iface = request.GET.get("iface")
    sniffer = get_sniffer()
    if iface:
        sniffer.start(iface)
    return JsonResponse({"status": "started", "iface": iface})


def stop_sniff(request):
    sniffer = get_sniffer()
    sniffer.stop()
    return JsonResponse({"status": "stopped"})


def status(request):
    sniffer = get_sniffer()
    active = sniffer.thread.is_alive() if sniffer.thread else False
    return JsonResponse({"active": active, "interface": sniffer.interface})


def interfaces(request):
    return JsonResponse({"interfaces": list_interfaces()})
