from fastapi import FastAPI
from fastapi.responses import HTMLResponse
from pathlib import Path

from security.detector import detect_brute_force

app = FastAPI()


def get_security_data():

    events = [
        {"type": "LOGIN_FAILED", "source": "192.168.1.10"},
        {"type": "LOGIN_FAILED", "source": "192.168.1.10"},
        {"type": "LOGIN_FAILED", "source": "192.168.1.10"},
        {"type": "LOGIN_FAILED", "source": "192.168.1.10"},
        {"type": "LOGIN_FAILED", "source": "192.168.1.10"},
    ]

    alerts = detect_brute_force(events)

    return events, alerts


@app.get("/", response_class=HTMLResponse)
def home():

    html = Path("templates/dashboard.html").read_text(
        encoding="utf-8"
    )

    events, alerts = get_security_data()

    critical = sum(
        1 for alert in alerts
        if alert["severity"] == "CRITICAL"
    )

    high = sum(
        1 for alert in alerts
        if alert["severity"] == "HIGH"
    )

    medium = sum(
        1 for alert in alerts
        if alert["severity"] == "MEDIUM"
    )

    html = html.replace(
        "{{CRITICAL}}",
        str(critical)
    )

    html = html.replace(
        "{{HIGH}}",
        str(high)
    )

    html = html.replace(
        "{{MEDIUM}}",
        str(medium)
    )

    if alerts:

        alert = alerts[0]

        alert_html = f"""
        <div>
            <h3>🚨 {alert["message"]}</h3>
            <p>Source: {alert["source"]}</p>
            <p>Failed Attempts: {alert["attempts"]}</p>
            <p>Severity: {alert["severity"]}</p>
        </div>
        """

    else:

        alert_html = "<p>🟢 No threats detected.</p>"

    html = html.replace(
        "{{ALERTS}}",
        alert_html
    )

    return html


@app.get("/test-security")
def test_security():

    events, alerts = get_security_data()

    return {
        "events_analyzed": len(events),
        "alerts": alerts
    }







@app.get("/events", response_class=HTMLResponse)
def events_page():
    return Path("templates/events.html").read_text(encoding="utf-8")
