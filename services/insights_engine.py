def generate_insights(insights_dict, sensitive_count):
    insights = []

    # Credit Card
    cc = insights_dict.get("credit_card", 0)
    if cc > 0:
        insights.append({
            "title": f"{cc} financial records detected",
            "description": "Files contain Credit Card information",
            "tag": "Critical"
        })

    # Sensitive Files
    if sensitive_count > 0:
        insights.append({
            "title": f"{sensitive_count} documents classified sensitive",
            "description": "Marked as Confidential / High Risk",
            "tag": "High"
        })

    # PII
    pii_count = (
        insights_dict.get("email", 0) +
        insights_dict.get("phone", 0)
    )

    if pii_count > 0:
        insights.append({
            "title": f"{pii_count} PII elements identified",
            "description": "Email / Phone data exposed",
            "tag": "Medium"
        })

    if not insights:
        insights.append({
            "title": "No critical risks detected",
            "description": "Uploaded files appear safe",
            "tag": "Low"
        })

    return insights