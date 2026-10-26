import os
import json
import urllib.request
import urllib.error

def check_google_safe_browsing(raw_url: str):
    """
    Optional Google Safe Browsing lookup.
    Requires GOOGLE_SAFE_BROWSING_API_KEY. Provider terms and eligibility must be checked
    before use. The application sends the submitted URL to Google when enabled.
    """
    api_key = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY")
    if not api_key:
        return {
            "status": "not_configured",
            "flagged": False,
            "message": "Threat-intelligence lookup is not configured."
        }

    endpoint = "https://safebrowsing.googleapis.com/v4/threatMatches:find?key=" + api_key
    body = {
        "client": {"clientId": "phishguard-student-project", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": raw_url}]
        }
    }
    req = urllib.request.Request(
        endpoint,
        data=json.dumps(body).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST"
    )
    try:
        with urllib.request.urlopen(req, timeout=3.0) as response:
            result = json.loads(response.read(256_000).decode("utf-8"))
        matches = result.get("matches", [])
        if matches:
            threat_types = sorted({m.get("threatType", "UNKNOWN") for m in matches})
            return {
                "status": "flagged",
                "flagged": True,
                "threat_types": threat_types,
                "message": "The reputation provider reported a threat match."
            }
        return {
            "status": "no_match",
            "flagged": False,
            "message": "No threat match was returned; this does not prove the URL is safe."
        }
    except (urllib.error.URLError, TimeoutError, OSError, ValueError) as exc:
        return {
            "status": "unavailable",
            "flagged": False,
            "message": "Threat-intelligence lookup failed or timed out; other checks were used.",
            "detail": str(exc)[:160]
        }
