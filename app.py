import os
import json


from flask import session
from datetime import datetime
from flask import Flask, render_template, request, redirect, session
from sqlalchemy import func
from werkzeug.utils import secure_filename
from textblob import TextBlob

from PyPDF2 import PdfReader
from docx import Document
from PIL import Image
import easyocr

from utils.detector import detect_sensitive_data
from services.risk_engine import calculate_risk
from services.insights_engine import generate_insights
from database.db import db
from database.models import File

from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib import colors
from reportlab.lib.units import inch
from reportlab.platypus import Table, TableStyle
from reportlab.lib.pagesizes import A4
from reportlab.platypus import ListFlowable, ListItem
from flask import send_file

# -------------------- App Configuration -------------------- #

app = Flask(__name__)

# Add these filters to your Flask app

@app.template_filter('risk_level')
def risk_level_filter(score):
    if score >= 7:
        return 'high'
    elif score >= 4:
        return 'medium'
    else:
        return 'low'

@app.template_filter('get_color_for_type')
def get_color_for_type(type_name):
    colors = {
        'PDF': '#ff6b6b',
        'DOC': '#667eea',
        'XLS': '#10b981',
        'CSV': '#feca57',
        'TXT': '#a8b8ff',
        'LOG': '#f72585'
    }
    return colors.get(type_name, '#667eea')

app.secret_key = "darkdata_secret"
app.secret_key = os.environ.get("SECRET_KEY", os.urandom(24))
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///files.db"
app.config["UPLOAD_FOLDER"] = "data/raw"

# Create upload folder if not exists
os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)

db.init_app(app)

with app.app_context():
    db.create_all()

# Load OCR model once
reader = easyocr.Reader(["en"])

def add_alert(file_name, issue, risk):
    if "alerts" not in session:
        session["alerts"] = []

    session["alerts"].insert(0, {
        "file_name": file_name,
        "issue": issue,
        "risk": risk,
        "time": datetime.now().strftime("%H:%M:%S")
    })


# -------------------- Routes -------------------- #

# 1️⃣ Home Page
@app.route("/")
def home():
    return render_template("index.html")


# 2️⃣ Upload Route
@app.route("/upload", methods=["POST"])
def upload():

    files = request.files.getlist("files")

    upload_count = 0
    sensitive_count = 0
    classification_dict = {}
    sensitive_file_ids = []

    total_sentiment = 0
    sentiment_files = 0
    sentiment_list = []

    for file in files:

        if not file or file.filename == "":
            continue

        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config["UPLOAD_FOLDER"], filename)
        file.save(filepath)

        file_extension = filename.split(".")[-1].lower()

        status = "processed"
        detection = {}
        risk_score = 0
        risk_level = "low"
        content = ""

        try:
            # -------- TXT / CSV -------- #
            if file_extension in ["txt", "csv"]:
                with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()

            # -------- PDF -------- #
            elif file_extension == "pdf":
                pdf_reader = PdfReader(filepath)
                for page in pdf_reader.pages:
                    text = page.extract_text()
                    if text:
                        content += text

            # -------- DOCX -------- #
            elif file_extension == "docx":
                doc = Document(filepath)
                content = "\n".join([para.text for para in doc.paragraphs])

            # -------- IMAGE OCR -------- #
            elif file_extension in ["png", "jpg", "jpeg"]:
                results = reader.readtext(filepath, detail=0)
                content = " ".join(results)

            # -------- SENTIMENT -------- #
            if content.strip():
                blob = TextBlob(content)
                polarity = round(blob.sentiment.polarity, 2)

                sentiment_list.append(polarity)
                total_sentiment += polarity
                sentiment_files += 1

            # -------- DETECTION + RISK -------- #
            if content:
                detection = detect_sensitive_data(content)
                risk_score, risk_level = calculate_risk(detection)

                if risk_score > 0:
                    status = "sensitive"
                    sensitive_count += 1
                    risk_level = risk_level.lower()

                    add_alert(
                        filename,
                        "Sensitive Data Detected",
                        risk_level
                    )

        except Exception as e:
            print(f"Processing error for {filename}: {e}")

        # -------- SAVE TO DATABASE -------- #
        new_file = File(
            filename=filename,
            filepath=filepath,
            status=status,
            file_type=file_extension,
            risk_score=risk_score,
            sensitive_data=json.dumps(detection)
        )

        db.session.add(new_file)
        db.session.flush()

        if status == "sensitive":
            sensitive_file_ids.append(new_file.id)

        upload_count += 1
        classification_dict[file_extension] = (
            classification_dict.get(file_extension, 0) + 1
        )

    db.session.commit()

    # -------- Store Session Data (Current User Only) -------- #
    avg_sentiment = round(total_sentiment / sentiment_files, 2) if sentiment_files > 0 else 0

    session["sentiment_score"] = avg_sentiment
    session["sentiment_list"] = sentiment_list
    session["current_user_count"] = upload_count
    session["classification"] = classification_dict
    session["sensitive_count"] = sensitive_count
    session["sensitive_file_ids"] = sensitive_file_ids

    return redirect("/dashboard")

# 3️⃣ Dashboard Route
@app.route("/dashboard")
def dashboard():

    # -------- Session Data -------- #
    user_count = session.get("current_user_count", 0)
    classification_dict = session.get("classification", {})
    sensitive_count = session.get("sensitive_count", 0)
    insights_dict = session.get("insights", {})
    sensitive_ids = session.get("sensitive_file_ids", [])

    sentiment_score = session.get("sentiment_score", 0)
    sentiment_list = session.get("sentiment_list", [])
    sentiment_labels = [f"File {i+1}" for i in range(len(sentiment_list))]

    summary_count = user_count

    # -------- Classification Percentage -------- #
    classification = []
    for file_type, count in classification_dict.items():
        percent = round((count / user_count) * 100, 2) if user_count > 0 else 0
        classification.append((file_type.upper(), percent))

    # -------- Risk Breakdown -------- #
    risk_summary = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0
    }

    if sensitive_ids:
        files = File.query.filter(File.id.in_(sensitive_ids)).all()

        for file in files:
            score = file.risk_score or 0

            if score > 70:
                risk_summary["critical"] += 1
            elif score > 40:
                risk_summary["high"] += 1
            elif score > 20:
                risk_summary["medium"] += 1
            else:
                risk_summary["low"] += 1

    # -------- AI Insights -------- #
    ai_insights = generate_insights(insights_dict, sensitive_count)

    if risk_summary["critical"] > 0:
        ai_insights.append({
            "title": "Critical Risk Files Detected",
            "description": f"{risk_summary['critical']} files require immediate attention.",
            "tag": "Critical"
        })
    elif risk_summary["high"] > 0:
        ai_insights.append({
            "title": "High Risk Exposure Found",
            "description": f"{risk_summary['high']} high-risk files identified.",
            "tag": "High"
        })
    elif risk_summary["medium"] > 0:
        ai_insights.append({
            "title": "Moderate Risk Identified",
            "description": f"{risk_summary['medium']} medium-risk files found.",
            "tag": "Medium"
        })
    elif risk_summary["low"] > 0:
        ai_insights.append({
            "title": "Low Risk Data Present",
            "description": f"{risk_summary['low']} low-risk files detected.",
            "tag": "Low"
        })

    # -------- Recent Alerts -------- #
    recent_alerts = []

    if sensitive_ids:
        files = File.query.filter(File.id.in_(sensitive_ids)).all()

        for file in files:
            score = file.risk_score or 0

            if score > 70:
                level = "critical"
                title = "Critical Sensitive Data Detected"
                icon = "fa-exclamation"
            elif score > 40:
                level = "high"
                title = "High Risk Data Found"
                icon = "fa-file-shield"
            elif score > 20:
                level = "medium"
                title = "Moderate Risk Identified"
                icon = "fa-credit-card"
            else:
                level = "low"
                title = "Low Risk Detected"
                icon = "fa-shield-alt"

            recent_alerts.append({
                "filename": file.filename,
                "level": level,
                "title": title,
                "icon": icon
            })

    # -------- Sentiment Analysis -------- #
    if sentiment_score > 0.2:
        sentiment_label = "Positive"
        sentiment_class = "positive"
    elif sentiment_score < -0.2:
        sentiment_label = "Negative"
        sentiment_class = "negative"
    else:
        sentiment_label = "Neutral"
        sentiment_class = "neutral"

    confidence = round(min(abs(sentiment_score) * 100, 100))
    trend = "Improving" if sentiment_score > 0 else "Declining"
    trend_icon = "fa-arrow-up" if sentiment_score > 0 else "fa-arrow-down"

    # -------- Render -------- #
    return render_template(
        "dashboard.html",
        processed_files=user_count,
        classification=classification,
        sensitive_count=sensitive_count,
        summary_count=summary_count,
        ai_insights=ai_insights,
        risk_summary=risk_summary,
        recent_alerts=recent_alerts,
        alerts=session.get("alerts", []),
        sentiment_score=sentiment_score,
        sentiment_label=sentiment_label,
        sentiment_class=sentiment_class,
        confidence=confidence,
        trend=trend,
        trend_icon=trend_icon,
        sentiment_list=sentiment_list,
        sentiment_labels=sentiment_labels,
    )

# 4️⃣ File Detection Status Route
@app.route("/file-detection-status")
def file_detection_status():

    sensitive_ids = session.get("sensitive_file_ids", [])

    total_files = File.query.order_by(File.id.desc()).limit(
        session.get("current_user_count", 0)
    ).all()

    file_status_list = []

    for file in total_files:

        if file.id in sensitive_ids:
            status = "Detected"
            status_class = "detected"
        else:
            status = "Not Detected"
            status_class = "clean"

        file_status_list.append({
            "filename": file.filename,
            "status": status,
            "status_class": status_class,
            "progress": 100
        })

    return render_template(
        "file_detection_status.html",
        files=file_status_list
    )

# 5️⃣ Sensitive Files Route
@app.route("/sensitive_files")
def sensitive_files():

    ids = session.get("sensitive_file_ids", [])

    db_files = File.query.filter(File.id.in_(ids)).all() if ids else []

    files = []

    for f in db_files:

        # Risk level convert
        if f.risk_score >= 70:
            status = "Critical"
        elif f.risk_score >= 40:
            status = "Warning"
        else:
            status = "Resolved"

        files.append({
            "filename": f.filename,
            "file_type": f.file_type.upper(),
            "status": status,
            "upload_time": "Just Now"
        })

    return render_template(
        "sensitive_files.html",
        files=files
    )


# 6️⃣ Summary Report Route
@app.route("/summary_report")
def summary_report():

    user_count = session.get("current_user_count", 0)
    sensitive_count = session.get("sensitive_count", 0)
    classification = session.get("classification", {})
    sensitive_ids = session.get("sensitive_file_ids", [])

    sensitive_files = (
        File.query.filter(File.id.in_(sensitive_ids)).all()
        if sensitive_ids else []
    )

    return render_template(
        "summary_report.html",
        total_files=user_count,
        sensitive_count=sensitive_count,
        classification=classification,
        sensitive_files=sensitive_files
    )

# 7️⃣ Export Report Route
@app.route("/export-report")
def export_report():

    filename = "AI_Dark_Data_Report.pdf"
    filepath = os.path.join(os.getcwd(), filename)

    doc = SimpleDocTemplate(filepath, pagesize=A4)
    elements = []
    styles = getSampleStyleSheet()

    # ---- SESSION DATA ----
    total_files = session.get("current_user_count", 0)
    sensitive_count = session.get("sensitive_count", 0)
    sentiment_score = session.get("sentiment_score", 0)
    sensitive_ids = session.get("sensitive_file_ids", [])

    # ---- TITLE ----
    elements.append(Paragraph("<b>AI Dark Data Mining System Report</b>", styles["Title"]))
    elements.append(Spacer(1, 0.3 * inch))

    # ---- DATE ----
    now = datetime.now().strftime("%d %B %Y - %H:%M")
    elements.append(Paragraph(f"Generated On: {now}", styles["Normal"]))
    elements.append(Spacer(1, 0.3 * inch))

    # ---- SUMMARY TABLE ----
    summary_data = [
        ["Metric", "Value"],
        ["Total Files Processed", str(total_files)],
        ["Sensitive Files", str(sensitive_count)],
        ["Sentiment Score", str(sentiment_score)],
    ]

    summary_table = Table(summary_data, colWidths=[250, 200])
    summary_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#667eea")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("ALIGN", (1, 1), (-1, -1), "CENTER"),
    ]))

    elements.append(summary_table)
    elements.append(Spacer(1, 0.5 * inch))

    # ---- RISK BREAKDOWN ----
    risk_summary = {
        "Critical": 0,
        "High": 0,
        "Medium": 0,
        "Low": 0
    }

    files = File.query.filter(File.id.in_(sensitive_ids)).all() if sensitive_ids else []

    for file in files:
        score = file.risk_score or 0
        if score > 70:
            risk_summary["Critical"] += 1
        elif score > 40:
            risk_summary["High"] += 1
        elif score > 20:
            risk_summary["Medium"] += 1
        else:
            risk_summary["Low"] += 1

    elements.append(Paragraph("<b>Risk Breakdown</b>", styles["Heading2"]))
    elements.append(Spacer(1, 0.2 * inch))

    risk_data = [["Level", "Count"]]
    for level, count in risk_summary.items():
        risk_data.append([level, str(count)])

    risk_table = Table(risk_data, colWidths=[250, 200])
    risk_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.darkgrey),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("ALIGN", (1, 1), (-1, -1), "CENTER"),
    ]))

    elements.append(risk_table)
    elements.append(Spacer(1, 0.5 * inch))

    # ---- SENSITIVE FILE DETAILS ----
    elements.append(Paragraph("<b>Sensitive File Details</b>", styles["Heading2"]))
    elements.append(Spacer(1, 0.2 * inch))

    if files:
        detailed_data = [["Filename", "Detected Sensitive Data"]]

        for file in files:
            detection_dict = json.loads(file.sensitive_data)

            detected_items = [
                key.upper()
                for key, value in detection_dict.items()
                if value is True
            ]

            detected_text = ", ".join(detected_items) if detected_items else "None"

            detailed_data.append([file.filename, detected_text])

        detailed_table = Table(detailed_data, colWidths=[220, 230])
        detailed_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f72585")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ]))

        elements.append(detailed_table)

    else:
        elements.append(Paragraph("No sensitive files detected.", styles["Normal"]))

    # ---- BUILD PDF ----
    doc.build(elements)

    return send_file(filepath, as_attachment=True)


# -------------------- Run App -------------------- #

if __name__ == "__main__":
    app.run(debug=True, use_reloader=False)