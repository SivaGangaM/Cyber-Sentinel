from collections import Counter


def detect_brute_force(events):

    failed_logins = [
        event for event in events
        if event.get("type") == "LOGIN_FAILED"
    ]

    sources = Counter(
        event.get("source", "unknown")
        for event in failed_logins
    )

    alerts = []

    for source, count in sources.items():

        if count >= 5:

            alerts.append({
                "type": "BRUTE_FORCE",
                "source": source,
                "attempts": count,
                "severity": "HIGH",
                "message": "Possible brute-force attack detected"
            })

    return alerts


if __name__ == "__main__":

    test_events = [
        {"type": "LOGIN_FAILED", "source": "192.168.1.10"},
        {"type": "LOGIN_FAILED", "source": "192.168.1.10"},
        {"type": "LOGIN_FAILED", "source": "192.168.1.10"},
        {"type": "LOGIN_FAILED", "source": "192.168.1.10"},
        {"type": "LOGIN_FAILED", "source": "192.168.1.10"},
    ]

    alerts = detect_brute_force(test_events)

    print("Detected Alerts:")
    print(alerts)
