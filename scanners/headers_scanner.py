import requests
from datetime import datetime

def scan_headers(url: str):
    required_headers = [
        "Content-Security-Policy",
        "X-Frame-Options",
        "X-Content-Type-Options"
    ]

    results = []
    r = requests.get(url, timeout=5)

    for header in required_headers:
        if header not in r.headers:
            results.append({
                "type": "Missing Security Header",
                "severity": 0,
                "target": header,
                "payload": None,
                "description": f"{header} header is missing.",
                "recommendation": f"Add {header} header.",
                "isConfirmed": True,
                "detectedAt": datetime.utcnow().isoformat(),
                "scannerName": "HeaderScanner"
            })

    return results
