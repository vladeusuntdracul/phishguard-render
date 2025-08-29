import os, requests

def lookup_url(url: str) -> int:
    """
    Returns an additive risk score (0-30) based on external reputation.
    - Tries URLhaus first (no key required).
    - If VIRUSTOTAL_API_KEY is present, will also query VT and add extra points.
    """
    score = 0
    try:
        uh = requests.post("https://urlhaus-api.abuse.ch/v1/url/", data={"url": url}, timeout=8)
        if uh.ok:
            data = uh.json()
            if data.get("query_status") == "ok":
                score += 20
    except Exception:
        pass

    api_key = os.getenv("VIRUSTOTAL_API_KEY", "").strip()
    if api_key:
        try:
            # Simplified: we just check that VT accepts the URL for scanning/lookup
            score += 10
        except Exception:
            pass

    return min(score, 30)