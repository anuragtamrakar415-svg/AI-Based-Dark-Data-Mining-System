import re

def detect_sensitive_data(text):

    results = {
        "credit_card": False,
        "email": False,
        "phone": False,
        "aadhaar": False,
        "pan": False,
        "bank_account": False,
        "ifsc": False,
        "passport": False,
        "upi": False
    }

    # 💳 Credit Card
    if re.search(r"\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b", text):
        results["credit_card"] = True

    # 📧 Email
    if re.search(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", text):
        results["email"] = True

    # 📞 Phone (10 digit India)
    if re.search(r"\b[6-9]\d{9}\b", text):
        results["phone"] = True

    # 🆔 Aadhaar (12 digit)
    if re.search(r"\b\d{4}\s?\d{4}\s?\d{4}\b", text):
        results["aadhaar"] = True

    # 🪪 PAN Card (ABCDE1234F)
    if re.search(r"\b[A-Z]{5}[0-9]{4}[A-Z]{1}\b", text):
        results["pan"] = True

    # 🏦 Bank Account (9–18 digit generic)
    if re.search(r"\b\d{9,18}\b", text):
        results["bank_account"] = True

    # 🏛 IFSC Code (4 letters + 0 + 6 digits)
    if re.search(r"\b[A-Z]{4}0[A-Z0-9]{6}\b", text):
        results["ifsc"] = True

    # 🌍 Passport (India format example)
    if re.search(r"\b[A-Z]{1}[0-9]{7}\b", text):
        results["passport"] = True

    # 💸 UPI ID
    if re.search(r"\b[\w.-]+@[\w.-]+\b", text):
        results["upi"] = True

    return results