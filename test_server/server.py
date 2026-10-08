from flask import Flask, request, redirect, render_template
from markupsafe import escape
import requests
import csv
from datetime import datetime
import re
from urllib.parse import urlparse
import joblib
import os
import cv2
import numpy as np
app = Flask(__name__)

AI_URL = "http://127.0.0.1:5000/predict"
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

LOG_FILE = os.path.join(BASE_DIR, "security_logs.csv")
FEEDBACK_FILE = os.path.join(BASE_DIR, "feedback.csv")
MESSAGE_MODEL_PATH = "../message_model/message_model.pkl"
MESSAGE_VECTORIZER_PATH = "../message_model/message_vectorizer.pkl"

message_model = joblib.load(MESSAGE_MODEL_PATH)
message_vectorizer = joblib.load(MESSAGE_VECTORIZER_PATH)
def save_log(url, action, risk_level, anomaly, patterns):
    file_exists = False

    try:
        with open(LOG_FILE, "r"):
            file_exists = True
    except FileNotFoundError:
        pass

    with open(LOG_FILE, "a", newline="", encoding="utf-8") as file:
        writer = csv.writer(file)

        if not file_exists:
            writer.writerow([
                "Time",
                "URL",
                "Decision",
                "Risk Level",
                "ML Score",
                "Detected Patterns"
            ])

        writer.writerow([
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            url,
            action,
            risk_level,
            round(anomaly, 2),
            ", ".join(patterns) if patterns else "None"
        ])
def save_feedback(url, original_decision, feedback):

    file_exists = False

    try:
        with open(FEEDBACK_FILE, "r"):
            file_exists = True
    except FileNotFoundError:
        pass

    with open(FEEDBACK_FILE, "a", newline="", encoding="utf-8") as file:
        writer = csv.writer(file)

        if not file_exists:
            writer.writerow([
                "Time",
                "URL",
                "Original Decision",
                "User Feedback"
            ])

        writer.writerow([
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            url,
            original_decision,
            feedback
        ])
def security_check(url):
    url_lower = url.lower()

    suspicious_patterns = [
        "' or ",
        "\" or ",
        "drop table",
        "union select",
        "<script",
        "javascript:",
        "../",
        "%3cscript",
        "%27%3b"
    ]

    detected = []

    for pattern in suspicious_patterns:
        if pattern in url_lower:
            detected.append(pattern)

    return detected

def explain_url_risk(url):
    reasons = []
    url_lower = url.lower()

    # HTTPS check
    if not url_lower.startswith("https://"):
        reasons.append("The URL does not use HTTPS")

    # @ symbol
    if "@" in url:
        reasons.append("The URL contains an @ symbol, which can hide the real destination")

    # Suspicious words
    suspicious_words = [
        "login",
        "verify",
        "update",
        "account",
        "password",
        "bank",
        "secure",
        "payment",
        "confirm"
    ]

    found_words = []

    for word in suspicious_words:
        if word in url_lower:
            found_words.append(word)

    if found_words:
        reasons.append(
            "Suspicious keywords found: " + ", ".join(found_words)
        )

    # Very long URL
    if len(url) > 100:
        reasons.append("The URL is unusually long")

    # Too many subdomain-like sections
    hostname = urlparse(url).hostname or ""

    is_ip_address = bool(
        re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", hostname)
    )

    if is_ip_address:
        reasons.append(
            "The URL uses an IP address instead of a domain name"
        )
    elif hostname.count(".") >= 3:
        reasons.append(
            "The URL contains many subdomain levels"
        )
    # Check whether the URL uses an IP address instead of a domain
    # Check for common URL shortening services
    shorteners = [
        "bit.ly",
        "tinyurl.com",
        "t.co",
        "goo.gl",
        "is.gd",
        "cutt.ly"
    ]

    hostname = urlparse(url).hostname or ""

    if any(shortener == hostname.lower() for shortener in shorteners):
        reasons.append(
            "The URL uses a shortening service that hides the final destination"
        )
    return reasons

def detect_domain_impersonation(url):
    hostname = (urlparse(url).hostname or "").lower()

    trusted_brands = {
        "google": "google.com",
        "paypal": "paypal.com",
        "amazon": "amazon.com",
        "microsoft": "microsoft.com",
        "apple": "apple.com",
        "instagram": "instagram.com",
        "facebook": "facebook.com"
    }

    warnings = []

    # Common substitutions used in lookalike domains
    replacements = {
        "0": "o",
        "1": "l",
        "3": "e",
        "5": "s",
        "7": "t"
    }

    normalized_hostname = hostname

    for fake_char, real_char in replacements.items():
        normalized_hostname = normalized_hostname.replace(
            fake_char,
            real_char
        )

    for brand, official_domain in trusted_brands.items():

        # Genuine official domain or subdomain
        if (
            hostname == official_domain
            or hostname.endswith("." + official_domain)
        ):
            continue

        # Exact brand name inside an unofficial domain
        if brand in hostname:
            warnings.append(
                f"Possible {brand.title()} impersonation: "
                f"this is not the official {official_domain} domain"
            )

        # Lookalike spelling such as g00gle or paypa1
        elif brand in normalized_hostname:
            warnings.append(
                f"Possible lookalike {brand.title()} domain detected"
            )

    return warnings

def analyze_url_security(url, user_agent=""):

    # Build HTTP request data for the AI backend
    data = {
        "Method": "GET",
        "User-Agent": user_agent,
        "host": "",
        "cookie": "",
        "content-type": "",
        "content": "",
        "URL": url
    }

    # Get HTTP anomaly score
    response = requests.post(
        AI_URL,
        json=data,
        timeout=5
    )

    result = response.json()

    anomaly = result["anomalous_probability"] * 100

    # Security analysis
    detected_patterns = security_check(url)
    url_reasons = explain_url_risk(url)

    impersonation_warnings = detect_domain_impersonation(url)

    if impersonation_warnings:
        url_reasons.extend(impersonation_warnings)
        # HIGH
    if detected_patterns:
        action = "BLOCK"
        risk_level = "HIGH"

        message = "This link contains a strong security warning sign."

        reason = (
            "WebSec detected a suspicious security pattern "
            "in the URL."
        )

    # MEDIUM - multiple URL indicators
    elif len(url_reasons) >= 2:
        action = "WARNING"
        risk_level = "MEDIUM"

        message = "This link has several characteristics that deserve caution."

        reason = (
            "WebSec found multiple URL warning indicators. "
            "Verify the destination before continuing."
        )

    # MEDIUM - high anomaly signal
    elif anomaly >= 60:
        action = "WARNING"
        risk_level = "MEDIUM"

        message = "This request looks unusual."

        reason = (
            "No known attack pattern was found, but the HTTP "
            "anomaly signal is above the current warning threshold."
        )

    # LOW
    else:
        action = "ALLOW"
        risk_level = "LOW"

        message = "No strong security threat was detected."

        if url_reasons:
            reason = (
                "WebSec found a minor URL warning indicator, "
                "but it was not enough to raise the current risk level."
            )
        else:
            reason = (
                "No suspicious URL patterns or additional URL "
                "warning indicators were detected."
            )

    return {
        "url": url,
        "action": action,
        "risk_level": risk_level,
        "message": message,
        "reason": reason,
        "anomaly": anomaly,
        "detected_patterns": detected_patterns,
        "url_reasons": url_reasons
    }

@app.route("/", methods=["GET", "POST"])
def gateway():

    # Show URL input page
    if request.method == "GET":
        return render_template("index.html")

    # Get URL entered by user
    url = request.form["url"].strip()

    # Add HTTPS if user did not enter a scheme
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    try:
        # Use shared WebSec URL security engine
        analysis = analyze_url_security(
            url,
            request.headers.get("User-Agent", "")
        )

    except requests.RequestException:
        return "<h2>AI backend is not available.</h2>"

    # Save result to security history
    save_log(
        analysis["url"],
        analysis["action"],
        analysis["risk_level"],
        analysis["anomaly"],
        analysis["detected_patterns"]
    )

    # Display result
    return render_template(
        "url_result.html",
        url=analysis["url"],
        action=analysis["action"],
        risk_level=analysis["risk_level"],
        message=analysis["message"],
        reason=analysis["reason"],
        anomaly=analysis["anomaly"],
        detected_patterns=analysis["detected_patterns"],
        url_reasons=analysis["url_reasons"],
        scan_source="link"
    )


@app.route("/feedback", methods=["POST"])
def feedback():

    url = request.form.get("url", "")
    decision = request.form.get("decision", "")

    save_feedback(
        url,
        decision,
        "Incorrect Classification"
    )

    return """
    <html>
    <body style="font-family:Arial; text-align:center; margin-top:100px;">

        <h1>Feedback Received</h1>

        <p>Thank you. The classification has been marked for review.</p>

        <p>
            Feedback will be stored for future model evaluation
            and will not automatically retrain the model.
        </p>

        <br>

        <a href="/">Back to Security Gateway</a>

    </body>
    </html>
    """
@app.route("/logs")
def view_logs():
    logs = []

    try:
        with open(LOG_FILE, "r", encoding="utf-8") as file:
            reader = csv.DictReader(file)
            logs = list(reader)

    except FileNotFoundError:
        pass

    return render_template(
        "logs.html",
        logs=logs
    )
@app.route("/dashboard")
def dashboard():

    try:
        with open(LOG_FILE, "r", encoding="utf-8") as file:
            reader = csv.DictReader(file)
            logs = list(reader)

    except FileNotFoundError:
        logs = []

    total = len(logs)
    allowed = sum(1 for log in logs if log["Decision"] == "ALLOW")
    warnings = sum(1 for log in logs if log["Decision"] == "WARNING")
    blocked = sum(1 for log in logs if log["Decision"] == "BLOCK")
    # Get latest 5 security events
    recent_logs = logs[-5:][::-1]

    recent_rows = ""

    for log in recent_logs:
        recent_rows += f"""
        <tr>
            <td>{escape(log["Time"])}</td>
            <td>{escape(log["URL"])}</td>
            <td>{escape(log["Decision"])}</td>
            <td>{escape(log["Risk Level"])}</td>
            <td>{escape(log["ML Score"])}%</td>
        </tr>
        """

    recent_logs = logs[-5:][::-1]

    return render_template(
        "dashboard.html",
        total=total,
        allowed=allowed,
        warnings=warnings,
        blocked=blocked,
        recent_logs=recent_logs
    )
def analyze_scam_message(message):
    text = message.lower()
    reasons = []
    score = 0

    urgency_words = [
        "urgent", "immediately", "act now",
        "within 24 hours", "limited time"
    ]

    credential_words = [
        "otp", "password", "pin",
        "verify your account", "login"
    ]

    payment_words = [
        "pay now", "payment", "send money",
        "processing fee", "bank details"
    ]

    threat_words = [
        "account blocked", "account suspended",
        "will be blocked", "legal action",
        "service terminated"
    ]

    prize_words = [
        "you won", "winner", "lottery",
        "claim prize", "congratulations"
    ]

    if any(word in text for word in urgency_words):
        reasons.append("Uses urgency to pressure the user")
        score += 1

    if any(word in text for word in credential_words):
        reasons.append("Requests or refers to sensitive account information")
        score += 1

    if any(word in text for word in payment_words):
        reasons.append("Contains a payment or money-related request")
        score += 1

    if any(word in text for word in threat_words):
        reasons.append("Uses threatening or fear-based language")
        score += 1

    if any(word in text for word in prize_words):
        reasons.append("Contains prize or reward-related language")
        score += 1

    if "http://" in text or "https://" in text or "www." in text:
        reasons.append("Contains a link")
        score += 1

    return score, reasons
def extract_urls_from_message(message):
    urls = re.findall(r'https?://[^\s]+', message)
    return urls
@app.route("/message", methods=["GET"])
def message_scanner():
    return render_template("message.html")

@app.route("/analyze-message", methods=["POST"])
def analyze_message():

    message = request.form.get("message", "")
    score, reasons = analyze_scam_message(message)
    extracted_urls = extract_urls_from_message(message)
    embedded_url_patterns = []
    embedded_url_reasons = []
    embedded_ml_score = None

    if extracted_urls:
        embedded_url = extracted_urls[0]

        try:
            embedded_analysis = analyze_url_security(
                embedded_url,
                request.headers.get("User-Agent", "")
            )

            embedded_url_patterns = embedded_analysis["detected_patterns"]
            embedded_url_reasons = embedded_analysis["url_reasons"]
            embedded_ml_score = embedded_analysis["anomaly"]

        except requests.RequestException:
            embedded_url_patterns = []
            embedded_url_reasons = []
            embedded_ml_score = None
    # ML analysis
    message_vector = message_vectorizer.transform([message])

    ml_probabilities = message_model.predict_proba(message_vector)[0]
    spam_probability = ml_probabilities[1] * 100
    # Hybrid decision using ML + explainable scam indicators
    if spam_probability >= 70 or score >= 4:
        risk = "HIGH"
        verdict = "Possible Scam"

    elif spam_probability >= 40 or score >= 2:
        risk = "MEDIUM"
        verdict = "Suspicious Message"

    else:
        risk = "LOW"
        verdict = "No Strong Scam Indicators"

    if risk == "HIGH":
        risk_color = "#dc2626"
        risk_bg = "#fef2f2"
        risk_icon = "🚨"

    elif risk == "MEDIUM":
        risk_color = "#d97706"
        risk_bg = "#fffbeb"
        risk_icon = "⚠️"

    else:
        risk_color = "#16a34a"
        risk_bg = "#f0fdf4"
        risk_icon = "✓"
    # Guardian AI recommendation
    if risk == "HIGH":
        guardian_message = (
            "This message shows multiple scam indicators. "
            "Do not click the link, share passwords or OTPs, or make payments. "
            "Verify the request using the organization's official website or app."
        )

    elif risk == "MEDIUM":
        guardian_message = (
            "This message contains some suspicious characteristics. "
            "Verify the sender and destination before clicking links or sharing information."
        )

    else:
        guardian_message = (
            "No strong scam indicators were detected. "
            "However, always verify unexpected requests before sharing sensitive information."
        )
    if reasons:
        reasons_html = "<br>".join(
            "⚠ " + str(escape(reason)) for reason in reasons
        )
    else:
        reasons_html = "✓ No common scam indicators detected."
    if extracted_urls:
        urls_html = "<br>".join(
            str(escape(url)) for url in extracted_urls
        )
    else:
        urls_html = "No URL detected."
    if embedded_url_patterns or embedded_url_reasons:
        url_analysis_items = []

        for pattern in embedded_url_patterns:
            url_analysis_items.append("Suspicious pattern: " + pattern)

        for reason in embedded_url_reasons:
            url_analysis_items.append(reason)

        url_analysis_html = "<br>".join(
            "⚠ " + str(escape(item))
            for item in url_analysis_items
        )
    else:
        url_analysis_html = "✓ No additional suspicious URL characteristics detected."
    if embedded_ml_score is not None:
        embedded_ml_text = f"{embedded_ml_score:.2f}%"
    else:
        embedded_ml_text = "Not available"
    safe_message = escape(message)

    return render_template(
        "message_result.html",
        message=message,
        risk=risk,
        verdict=verdict,
        guardian_message=guardian_message,
        reasons=reasons,
        score=score,
        spam_probability=spam_probability,
        extracted_urls=extracted_urls,
        embedded_url_patterns=embedded_url_patterns,
        embedded_url_reasons=embedded_url_reasons,
        embedded_ml_score=embedded_ml_score
    )


@app.route("/qr")
def qr_scanner():
    return render_template("qr.html")


@app.route("/analyze-qr", methods=["POST"])
def analyze_qr():

    # Check whether an image was uploaded
    if "qr_image" not in request.files:
        return "No QR image uploaded."

    file = request.files["qr_image"]

    if file.filename == "":
        return "No QR image selected."

    try:
        # Convert uploaded image into an OpenCV image
        image_bytes = np.frombuffer(file.read(), np.uint8)
        image = cv2.imdecode(image_bytes, cv2.IMREAD_COLOR)

        if image is None:
            return "Unable to read the uploaded image."

        # Detect and decode QR code
        detector = cv2.QRCodeDetector()

        qr_data, points, _ = detector.detectAndDecode(image)

        if not qr_data:
            return """
            <h2>No QR code detected</h2>
            <p>WebSec could not find a readable QR code in this image.</p>
            <a href="/qr">Try another image</a>
            """

       # Make sure the QR contains a web URL
        # Check whether QR contains a URL
        if not qr_data.startswith(("http://", "https://")):
            return f"""
            <h2>QR Code Detected</h2>
            <p>This QR code does not contain a web link.</p>
            <p><b>Content:</b> {escape(qr_data)}</p>
            <a href="/qr">Scan another QR</a>
            """

        try:
            # Analyze decoded URL using WebSec's shared security engine
            analysis = analyze_url_security(
                qr_data,
                request.headers.get("User-Agent", "")
            )

        except requests.RequestException:
            return "<h2>AI backend is not available.</h2>"

        # Save QR URL analysis in security history
        save_log(
            analysis["url"],
            analysis["action"],
            analysis["risk_level"],
            analysis["anomaly"],
            analysis["detected_patterns"]
        )

        # Display using our existing URL result page
        return render_template(
            "url_result.html",
            url=analysis["url"],
            action=analysis["action"],
            risk_level=analysis["risk_level"],
            message=analysis["message"],
            reason=analysis["reason"],
            anomaly=analysis["anomaly"],
            detected_patterns=analysis["detected_patterns"],
            url_reasons=analysis["url_reasons"],
            scan_source="qr"
        )
    except Exception as error:
            print("QR ERROR:", error)
    return "WebSec could not process this QR image."
if __name__ == "__main__":
    app.run(port=8000, debug=True)