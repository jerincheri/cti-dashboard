def calculate_threat_level(ioc_type, tags):
    score = 0

    if ioc_type in ["IPv4", "domain"]:
        score += 2
    elif ioc_type in ["URL", "hostname"]:
        score += 3
    elif ioc_type in ["FileHash-SHA256", "FileHash-MD5"]:
        score += 4

    high_threat_tags = ["APT", "Ransomware", "C2", "Malware", "Phishing"]
    score += sum(2 for tag in tags if tag in high_threat_tags)

    # Normalize
    if score >= 7:
        return "High"
    elif score >= 4:
        return "Medium"
    else:
        return "Low"
