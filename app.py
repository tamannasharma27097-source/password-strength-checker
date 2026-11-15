"""
app.py
------
Main Flask application entry point for the
"Advanced Password Strength & Breach Detection System".

Student   : Tamanna
Training  : 1 Month Cyber Security Training
Guide     : Cyber Security Department

Run with:
    pip install -r requirements.txt
    python app.py

Then open http://127.0.0.1:5000 in your browser.

This app is 100% OFFLINE - no external APIs or databases are used.
"""
import os
import io
import random
from datetime import datetime

from flask import Flask, render_template, request, jsonify, send_file

from password_checker import analyze_password, get_security_suggestions
from breach_checker import check_breach, dataset_size
from password_generator import generate_password

from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER

app = Flask(__name__)
app.config["JSON_SORT_KEYS"] = False

REPORTS_DIR = os.path.join(os.path.dirname(__file__), "reports")
os.makedirs(REPORTS_DIR, exist_ok=True)

STUDENT_NAME = "Tamanna"
TRAINING_NAME = "1 Month Cyber Security Training"
GUIDE_NAME = "Cyber Security Department"
PROJECT_TITLE = "Advanced Password Strength & Breach Detection System"

CYBER_TIPS = [
    "Never share your password with anyone, even IT support.",
    "Enable Multi-Factor Authentication (MFA) on every important account.",
    "A password manager is safer than reusing the same password everywhere.",
    "Public Wi-Fi is a common place for credential theft — use a VPN.",
    "Phishing emails often create fake urgency — always verify the sender.",
    "Longer passwords beat complex-but-short ones for real-world security.",
    "Change default router and IoT device passwords immediately.",
    "Regularly check if your accounts appear in known data breaches.",
    "Lock your screen every time you step away from your device.",
    "Keep your operating system and software updated with security patches.",
]


@app.route("/")
def index():
    """Landing page + main dashboard (single page app)."""
    return render_template(
        "index.html",
        student_name=STUDENT_NAME,
        training_name=TRAINING_NAME,
        guide_name=GUIDE_NAME,
        project_title=PROJECT_TITLE,
        dataset_size=dataset_size(),
    )


@app.route("/api/check", methods=["POST"])
def api_check():
    """
    Main analysis endpoint. Accepts a password, runs strength analysis
    AND local breach detection, and returns everything the dashboard needs
    in one response.
    """
    data = request.get_json(silent=True) or {}
    password = data.get("password", "")

    analysis = analyze_password(password)
    suggestions = get_security_suggestions(analysis)
    breach_result = check_breach(password)

    response = {
        "analysis": analysis,
        "suggestions": suggestions,
        "breach": breach_result,
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }
    return jsonify(response)


@app.route("/api/generate", methods=["POST"])
def api_generate():
    """Secure password generator endpoint."""
    data = request.get_json(silent=True) or {}

    length = int(data.get("length", 16))
    use_upper = bool(data.get("uppercase", True))
    use_lower = bool(data.get("lowercase", True))
    use_numbers = bool(data.get("numbers", True))
    use_symbols = bool(data.get("symbols", True))
    exclude_similar = bool(data.get("exclude_similar", False))
    exclude_ambiguous = bool(data.get("exclude_ambiguous", False))

    pwd = generate_password(
        length=length,
        use_upper=use_upper,
        use_lower=use_lower,
        use_numbers=use_numbers,
        use_symbols=use_symbols,
        exclude_similar=exclude_similar,
        exclude_ambiguous=exclude_ambiguous,
    )
    analysis = analyze_password(pwd)

    return jsonify({"password": pwd, "analysis": analysis})


@app.route("/api/tip", methods=["GET"])
def api_tip():
    """Return a random cyber security tip for the dashboard widget."""
    return jsonify({"tip": random.choice(CYBER_TIPS)})


@app.route("/api/export", methods=["POST"])
def api_export():
    """
    Generate a professional PDF report of the latest password analysis
    using ReportLab, and stream it back to the browser as a download.
    """
    data = request.get_json(silent=True) or {}
    password_masked = "•" * len(data.get("password", "")) or "N/A"
    analysis = data.get("analysis", {})
    breach = data.get("breach", {})
    suggestions = data.get("suggestions", [])

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer, pagesize=A4,
        topMargin=20 * mm, bottomMargin=20 * mm,
        leftMargin=18 * mm, rightMargin=18 * mm,
    )

    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        "TitleStyle", parent=styles["Title"],
        textColor=colors.HexColor("#0b3d2e"), fontSize=20, alignment=TA_CENTER,
        spaceAfter=6,
    )
    subtitle_style = ParagraphStyle(
        "SubtitleStyle", parent=styles["Normal"],
        textColor=colors.HexColor("#333333"), fontSize=11, alignment=TA_CENTER,
        spaceAfter=2,
    )
    section_style = ParagraphStyle(
        "SectionStyle", parent=styles["Heading2"],
        textColor=colors.HexColor("#0b6e4f"), fontSize=13, spaceBefore=14,
        spaceAfter=6,
    )
    body_style = styles["Normal"]

    elements = []
    elements.append(Paragraph("VPROTECH DIGITAL", subtitle_style))
    elements.append(Paragraph(PROJECT_TITLE, title_style))
    elements.append(HRFlowable(width="100%", color=colors.HexColor("#00e08f"), thickness=1.2))
    elements.append(Spacer(1, 8))

    meta_table_data = [
        ["Student Name", STUDENT_NAME, "Training", TRAINING_NAME],
        ["Guide", GUIDE_NAME, "Report Date", datetime.now().strftime("%d %B %Y, %H:%M")],
    ]
    meta_table = Table(meta_table_data, colWidths=[70 * mm, 55 * mm, 40 * mm, 45 * mm])
    meta_table.setStyle(TableStyle([
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("TEXTCOLOR", (0, 0), (0, -1), colors.HexColor("#0b6e4f")),
        ("TEXTCOLOR", (2, 0), (2, -1), colors.HexColor("#0b6e4f")),
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTNAME", (2, 0), (2, -1), "Helvetica-Bold"),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#cccccc")),
    ]))
    elements.append(meta_table)
    elements.append(Spacer(1, 10))

    elements.append(Paragraph("1. Password Analysis Summary", section_style))
    analysis_rows = [
        ["Field", "Value"],
        ["Password (masked)", password_masked],
        ["Strength Level", analysis.get("strength_label", "N/A")],
        ["Security Score", f"{analysis.get('strength_score', 'N/A')} / 100"],
        ["Entropy", f"{analysis.get('entropy', 'N/A')} bits"],
        ["Length", str(analysis.get("password_length", "N/A"))],
        ["Uppercase Count", str(analysis.get("uppercase_count", "N/A"))],
        ["Lowercase Count", str(analysis.get("lowercase_count", "N/A"))],
        ["Number Count", str(analysis.get("number_count", "N/A"))],
        ["Special Character Count", str(analysis.get("special_count", "N/A"))],
        ["Unique Characters", str(analysis.get("unique_characters", "N/A"))],
        ["Repeated Characters", str(analysis.get("repeated_characters", "N/A"))],
        ["Dictionary Word Detected", "Yes" if analysis.get("is_dictionary_word") else "No"],
        ["Sequential Pattern Detected", "Yes" if analysis.get("is_sequential") else "No"],
        ["Keyboard Pattern Detected", "Yes" if analysis.get("is_keyboard_pattern") else "No"],
        ["Estimated Crack Time", analysis.get("crack_time_display", "N/A")],
    ]
    analysis_table = Table(analysis_rows, colWidths=[70 * mm, 100 * mm])
    analysis_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0b3d2e")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#eef7f2")]),
        ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#cccccc")),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
    ]))
    elements.append(analysis_table)
    elements.append(Spacer(1, 10))

    elements.append(Paragraph("2. Breach Detection Result", section_style))
    if breach.get("found"):
        breach_rows = [
            ["Field", "Value"],
            ["Status", "FOUND IN LOCAL BREACH DATASET"],
            ["Risk Level", breach.get("risk_level", "N/A")],
            ["Estimated Breach Year", str(breach.get("breach_year", "N/A"))],
            ["Times Exposed", str(breach.get("exposure_count", "N/A"))],
            ["Source (Demo)", breach.get("source_name", "N/A")],
        ]
    else:
        breach_rows = [
            ["Field", "Value"],
            ["Status", "No known breach found in local dataset."],
        ]
    breach_table = Table(breach_rows, colWidths=[70 * mm, 100 * mm])
    breach_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#5c1414")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#fbeaea")]),
        ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#cccccc")),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
    ]))
    elements.append(breach_table)
    elements.append(Spacer(1, 4))
    elements.append(Paragraph(
        "<i>" + breach.get("disclaimer", "This is only an offline demonstration.") + "</i>",
        ParagraphStyle("disclaimer", parent=body_style, fontSize=8, textColor=colors.grey),
    ))
    elements.append(Spacer(1, 10))

    elements.append(Paragraph("3. Security Suggestions", section_style))
    for s in suggestions:
        elements.append(Paragraph(f"• {s}", body_style))

    elements.append(Spacer(1, 16))
    elements.append(HRFlowable(width="100%", color=colors.HexColor("#cccccc"), thickness=0.6))
    elements.append(Spacer(1, 4))
    elements.append(Paragraph(
        "Generated by Advanced Password Strength & Breach Detection System | "
        "Vprotech Digital Cyber Security Training | Fully offline, local analysis only.",
        ParagraphStyle("footer", parent=body_style, fontSize=8, alignment=TA_CENTER,
                        textColor=colors.grey),
    ))

    doc.build(elements)
    buffer.seek(0)

    filename = f"Password_Security_Report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
    return send_file(
        buffer, as_attachment=True, download_name=filename, mimetype="application/pdf"
    )


if __name__ == "__main__":
    app.run(debug=True, host="127.0.0.1", port=5000)
