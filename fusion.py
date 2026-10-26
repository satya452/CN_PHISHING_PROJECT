def combine_signals(parsed, dns, rules, reputation):
    """
    Fuse transparent rules with optional threat intelligence.
    DNS resolution is displayed but does not itself add or subtract risk points.
    """
    score = int(rules["score"])
    reasons = list(rules["reasons"])

    if reputation.get("flagged"):
        score = max(score, 85)
        reasons.append({
            "points": None,
            "reason": "Threat-intelligence provider returned a positive threat match."
        })

    score = max(0, min(100, score))
    if reputation.get("flagged") or score >= 60:
        band = "High"
        advice = "Do not open the link or enter information. Verify the destination through an official channel."
    elif score >= 30:
        band = "Medium"
        advice = "Treat the link cautiously. Navigate to the service by typing its known official address."
    else:
        band = "Low observed risk"
        advice = "No strong indicators were detected by the configured checks. This is not a safety guarantee."

    if not reasons:
        reasons = [{"points": 0, "reason": "No configured URL heuristic was triggered."}]

    return {
        "risk_score": score,
        "risk_band": band,
        "reasons": reasons,
        "dns_status": dns.get("status", "unknown"),
        "reputation": reputation,
        "advice": advice,
        "features": parsed["features"],
    }
