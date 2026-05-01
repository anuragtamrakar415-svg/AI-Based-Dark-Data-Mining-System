from database.db import db
from datetime import datetime
import json

# -----------------------------
# 📁 FILE TABLE
# -----------------------------
class File(db.Model):
    id = db.Column(db.Integer, primary_key=True)

    filename = db.Column(db.String(300), nullable=False)
    filepath = db.Column(db.String(300), nullable=False)
    file_type = db.Column(db.String(50))

    status = db.Column(db.String(50))  # processed / sensitive

    risk_score = db.Column(db.Integer, default=0)

    sensitive_data = db.Column(db.Text)  # JSON stored as string

    upload_time = db.Column(db.DateTime, default=datetime.utcnow)

    alerts = db.relationship("Alert", backref="file", lazy=True)


# -----------------------------
# 🚨 ALERT TABLE
# -----------------------------
class Alert(db.Model):
    id = db.Column(db.Integer, primary_key=True)

    file_id = db.Column(db.Integer, db.ForeignKey('file.id'), nullable=False)

    alert_type = db.Column(db.String(100))   # credit_card / pan / etc
    severity = db.Column(db.String(50))      # Low / Medium / High / Critical
    message = db.Column(db.String(500))

    timestamp = db.Column(db.DateTime, default=datetime.utcnow)


# -----------------------------
# 📊 REPORT TABLE
# -----------------------------
class Report(db.Model):
    id = db.Column(db.Integer, primary_key=True)

    total_files = db.Column(db.Integer)
    sensitive_files = db.Column(db.Integer)

    overall_risk_score = db.Column(db.Integer)
    risk_level = db.Column(db.String(50))

    generated_at = db.Column(db.DateTime, default=datetime.utcnow)