import requests
from datetime import datetime

def scan_xss(url: str):
    payload = "<script>alert(1)</script>"
    results = []

    test_url = f"{url}?q={payload}"
    try:
        r = requests.get(test_url, timeout=5)
        if payload in r.text:
            results.append({
                "type": "XSS",
                "severity": 1,
                "target": test_url,
                "payload": payload,
                "description": "Reflected XSS vulnerability detected.",
                "recommendation": "Encode output and use CSP.",
                "isConfirmed": True,
                "detectedAt": datetime.utcnow().isoformat(),
                "scannerName": "XSSScanner"
            })
    except:
        pass

    return results
