# services/risk_engine.py

def calculate_risk(detection_dict):
    """
    detection_dict example:
    {
        "credit_card": 2,
        "pan": 1,
        "email": 3
    }
    """

    score = 0

    weights = {
        "credit_card": 25,
        "aadhaar": 20,
        "pan": 15,
        "bank_account": 15,
        "ifsc": 10,
        "upi": 10,
        "email": 5,
        "phone": 5
    }

    for key, count in detection_dict.items():
        if key in weights:
            score += weights[key] * count

    # Risk Level Logic
    if score <= 20:
        level = "Low"
    elif score <= 40:
        level = "Medium"
    elif score <= 70:
        level = "High"
    else:
        level = "Critical"

    return score, level

