def score_rules(parsed):
    """Transparent starter heuristic. Weights should be calibrated with test data."""
    f = parsed["features"]
    score = 0
    reasons = []

    def add(points, reason):
        nonlocal score
        score += points
        reasons.append({"points": points, "reason": reason})

    if f["ip_literal"]:
        add(15, "The hostname is an IP address rather than a domain name.")
    if f["subdomain_count"] >= 4:
        add(8, "The hostname has many subdomain labels, which can obscure the main domain.")
    if f["punycode"]:
        add(10, "The hostname contains punycode; inspect it for look-alike characters.")
    if f["at_symbol"]:
        add(12, "The URL contains '@', which can make the apparent destination misleading.")
    if f["url_length"] >= 100:
        add(8, "The URL is unusually long.")
    elif f["url_length"] >= 75:
        add(4, "The URL is relatively long.")
    if f["hyphen_count"] >= 3:
        add(5, "The hostname contains several hyphens.")
    if f["encoded_chars"]:
        add(4, "The URL contains percent-encoded characters.")
    if f["double_slash_path"]:
        add(4, "The path contains a repeated slash pattern.")
    if f["suspicious_terms"]:
        add(5, "The URL contains a term often seen in account or credential workflows.")
    if f["numeric_hostname"]:
        add(10, "The hostname looks numeric.")

    # HTTPS is intentionally not a positive trust signal: phishing sites can use HTTPS.
    score = min(score, 100)
    return {"score": score, "reasons": reasons}
