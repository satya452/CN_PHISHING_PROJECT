import ipaddress
import socket
import time

def check_dns(hostname: str):
    """Resolve a hostname only; never fetch the website or follow redirects."""
    try:
        ipaddress.ip_address(hostname.strip("[]"))
        return {
            "status": "ip_literal",
            "addresses": [hostname],
            "message": "The URL already contains an IP address; DNS lookup was not needed."
        }
    except ValueError:
        pass

    started = time.perf_counter()
    old_timeout = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(2.0)
        results = socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)
        addresses = sorted({item[4][0] for item in results})
        return {
            "status": "resolved" if addresses else "no_answer",
            "addresses": addresses[:10],
            "message": "Hostname resolved successfully." if addresses else "No address records returned.",
            "duration_ms": round((time.perf_counter() - started) * 1000, 2)
        }
    except socket.gaierror as exc:
        # Avoid overinterpreting DNS errors: they do not prove phishing.
        return {
            "status": "resolution_error",
            "addresses": [],
            "message": "DNS resolution failed or returned no usable address.",
            "detail": str(exc)[:160],
            "duration_ms": round((time.perf_counter() - started) * 1000, 2)
        }
    except (TimeoutError, OSError) as exc:
        return {
            "status": "timeout_or_network_error",
            "addresses": [],
            "message": "DNS lookup timed out or the resolver could not be reached.",
            "detail": str(exc)[:160],
            "duration_ms": round((time.perf_counter() - started) * 1000, 2)
        }
    finally:
        socket.setdefaulttimeout(old_timeout)
