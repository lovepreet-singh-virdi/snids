from django import template
from django.utils import timezone

register = template.Library()


@register.filter
def human_time(value):
    """
    Same-day: if <1h => "x minutes ago"; else "today HH:MM AM/PM".
    Other-day: "YYYY-MM-DD HH:MM AM/PM".
    """
    if value is None:
        return ""
    now = timezone.localtime()
    ts = timezone.localtime(value)
    delta = (now - ts).total_seconds()
    if ts.date() == now.date():
        if delta < 3600:
            from django.template.defaultfilters import timesince
            return f"{timesince(ts, now)} ago"
        return ts.strftime("Today %I:%M %p").lstrip("0").replace(" 0", " ")
    else:
        # previous days
        if delta < 3600:
            from django.template.defaultfilters import timesince
            return f"{timesince(ts, now)} ago"
        return ts.strftime("%Y-%m-%d %I:%M %p").lstrip("0").replace(" 0", " ")
