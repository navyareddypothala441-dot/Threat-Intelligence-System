def _safe_int(
    value,
    default=0
):
    try:
        return int(
            value or 0
        )

    except (
        TypeError,
        ValueError
    ):
        return default


def calculate_risk_score(
    vt_data=None,
    abuse_data=None,
    related_ioc_count=0,
    multiple_sources=False,
    recent_activity=False
):
    vt_data = (
        vt_data
        if isinstance(
            vt_data,
            dict
        )
        else {}
    )

    abuse_data = (
        abuse_data
        if isinstance(
            abuse_data,
            dict
        )
        else {}
    )

    score = 0
    reasons = []

    # =====================================================
    # VIRUSTOTAL
    # =====================================================

    malicious = _safe_int(
        vt_data.get(
            "malicious"
        )
    )

    suspicious = _safe_int(
        vt_data.get(
            "suspicious"
        )
    )

    harmless = _safe_int(
        vt_data.get(
            "harmless"
        )
    )

    undetected = _safe_int(
        vt_data.get(
            "undetected"
        )
    )

    total_engines = (
        malicious
        + suspicious
        + harmless
        + undetected
    )

    malicious_ratio = 0

    if total_engines > 0:
        malicious_ratio = (
            malicious
            / total_engines
        )

    if malicious >= 50:
        score += 70

        reasons.append(
            f"VirusTotal reported "
            f"{malicious} malicious "
            f"detection(s). +70"
        )

    elif malicious >= 20:
        score += 55

        reasons.append(
            f"VirusTotal reported "
            f"{malicious} malicious "
            f"detection(s). +55"
        )

    elif malicious >= 10:
        score += 40

        reasons.append(
            f"VirusTotal reported "
            f"{malicious} malicious "
            f"detection(s). +40"
        )

    elif malicious >= 3:
        score += 25

        reasons.append(
            f"VirusTotal reported "
            f"{malicious} malicious "
            f"detection(s). +25"
        )

    elif malicious > 0:
        # For weak URL detections,
        # consider ratio to reduce
        # false positives.

        if (
            total_engines > 0
            and malicious_ratio < 0.05
        ):
            score += 10

            reasons.append(
                f"VirusTotal reported "
                f"{malicious} low-ratio "
                f"malicious detection(s). "
                f"+10"
            )

        else:
            score += 15

            reasons.append(
                f"VirusTotal reported "
                f"{malicious} malicious "
                f"detection(s). +15"
            )

    if suspicious >= 5:
        score += 15

        reasons.append(
            f"VirusTotal reported "
            f"{suspicious} suspicious "
            f"detection(s). +15"
        )

    elif suspicious > 0:
        score += 5

        reasons.append(
            f"VirusTotal reported "
            f"{suspicious} suspicious "
            f"detection(s). +5"
        )

    # Security-related tags

    tags = vt_data.get(
        "tags",
        []
    )

    suspicious_tags = {
        "malware",
        "phishing",
        "trojan",
        "ransomware",
        "botnet",
        "spyware",
        "exploit",
        "powershell",
        "via-tor",
        "attachment"
    }

    if isinstance(
        tags,
        list
    ):
        detected_tags = (
            suspicious_tags
            .intersection(
                set(
                    str(tag).lower()
                    for tag in tags
                )
            )
        )

        if detected_tags:
            score += 10

            reasons.append(
                "VirusTotal contains "
                "security-related "
                "suspicious tag(s). +10"
            )

    # Reputation

    reputation = _safe_int(
        vt_data.get(
            "reputation"
        )
    )

    if reputation < -50:
        score += 15

        reasons.append(
            "VirusTotal reputation "
            "is strongly negative. +15"
        )

    elif reputation < 0:
        score += 5

        reasons.append(
            "VirusTotal reputation "
            "is negative. +5"
        )

    # =====================================================
    # ABUSEIPDB
    # =====================================================

    abuse_score = _safe_int(
        abuse_data.get(
            "abuse_confidence_score"
        )
    )

    total_reports = _safe_int(
        abuse_data.get(
            "total_reports"
        )
    )

    if abuse_score >= 90:
        score += 30

        reasons.append(
            "AbuseIPDB confidence "
            f"score is {abuse_score}. "
            "+30"
        )

    elif abuse_score >= 70:
        score += 20

        reasons.append(
            "AbuseIPDB confidence "
            f"score is {abuse_score}. "
            "+20"
        )

    elif abuse_score >= 40:
        score += 10

        reasons.append(
            "AbuseIPDB confidence "
            f"score is {abuse_score}. "
            "+10"
        )

    if total_reports >= 100:
        score += 15

        reasons.append(
            f"IP has {total_reports} "
            "AbuseIPDB reports. +15"
        )

    elif total_reports >= 20:
        score += 10

        reasons.append(
            f"IP has {total_reports} "
            "AbuseIPDB reports. +10"
        )

    elif total_reports > 0:
        score += 5

        reasons.append(
            f"IP has {total_reports} "
            "AbuseIPDB reports. +5"
        )

    # =====================================================
    # RECENT ACTIVITY
    # =====================================================

    if recent_activity:
        score += 5

        reasons.append(
            "Recent threat activity "
            "was reported. +5"
        )

    # =====================================================
    # CORRELATION
    # =====================================================

    related_ioc_count = _safe_int(
        related_ioc_count
    )

    if related_ioc_count >= 20:
        score += 10

        reasons.append(
            "Large IOC relationship "
            "cluster detected. +10"
        )

    elif related_ioc_count >= 5:
        score += 5

        reasons.append(
            "Multiple related IOCs "
            "were discovered. +5"
        )

    # =====================================================
    # MULTI SOURCE
    # =====================================================

    if multiple_sources:
        reasons.append(
            "Multiple intelligence "
            "sources successfully "
            "responded."
        )

    # =====================================================
    # LIMIT 0-100
    # =====================================================

    score = max(
        0,
        min(
            score,
            100
        )
    )

    # =====================================================
    # LEVEL
    # =====================================================

    if score <= 20:
        level = "LOW"

    elif score <= 40:
        level = "MEDIUM"

    elif score <= 60:
        level = "SUSPICIOUS"

    elif score <= 80:
        level = "HIGH"

    else:
        level = "CRITICAL"

    if not reasons:
        reasons.append(
            "No significant threat "
            "indicators were detected."
        )

    return {
        "score": score,
        "level": level,
        "reasons": reasons
    }