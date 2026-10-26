import ipaddress
import re
from urllib.parse import urlsplit, unquote

ALLOWED_SCHEMES = {"http", "https"}

def analyze_url(raw_url: str):
    """Validate and parse a URL without making a network request."""
    if not raw_url:
        return None, "Enter a URL to scan."
    if len(raw_url) > 4096:
        return None, "URL is too long (maximum 4096 characters)."

    candidate = raw_url if "://" in raw_url else "http://" + raw_url
    try:
        parts = urlsplit(candidate)
        scheme = (parts.scheme or "").lower()
        if scheme not in ALLOWED_SCHEMES:
            return None, "Only http:// and https:// URLs are supported."
        if not parts.netloc or not parts.hostname:
            return None, "The URL must include a valid hostname."
        # Accessing .port can raise ValueError for malformed ports.
        _ = parts.port
        hostname = parts.hostname.rstrip(".").lower()
        if not hostname or any(ch.isspace() for ch in hostname):
            return None, "The hostname is invalid."
        try:
            ipaddress.ip_address(hostname.strip("[]"))
            is_ip = True
        except ValueError:
            is_ip = False
        decoded = unquote(raw_url)
        labels = [label for label in hostname.split(".") if label]
        path_query = (parts.path or "") + ("?" + parts.query if parts.query else "")
        features = {
            "url_length": len(raw_url),
            "hostname_length": len(hostname),
            "dot_count": hostname.count("."),
            "subdomain_count": max(0, len(labels) - 2),
            "hyphen_count": hostname.count("-"),
            "at_symbol": "@" in raw_url,
            "ip_literal": is_ip,
            "https": scheme == "https",
            "punycode": "xn--" in hostname,
            "encoded_chars": "%" in raw_url,
            "double_slash_path": "//" in (parts.path or ""),
            "suspicious_terms": bool(re.search(
                r"(login|verify|account|password|secure|update|wallet|signin|confirm|payment)",
                (hostname + " " + path_query).lower()
            )),
            "numeric_hostname": bool(re.fullmatch(r"[0-9.]+", hostname)),
            "decoded_at_symbol": "@" in decoded,
        }
        return {
            "raw": raw_url,
            "normalized": candidate,
            "scheme": scheme,
            "hostname": hostname,
            "path": parts.path or "/",
            "query": parts.query,
            "features": features,
        }, None
    except ValueError:
        return None, "The URL or port is malformed."
