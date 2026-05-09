from flask import Flask, render_template, request
import re

app = Flask(__name__)

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/check', methods=['POST'])
def check():

    email_text = request.form['email'].lower()

    score = 0
    threats = []

    # Suspicious Keywords
    suspicious_keywords = [
        'urgent',
        'verify your account',
        'password reset',
        'click below',
        'bank account',
        'security alert',
        'limited time',
        'login immediately',
        'suspended',
        'confirm identity',
        'otp',
        'winner',
        'claim prize',
        'free money',
        'bitcoin'
    ]

    for keyword in suspicious_keywords:
        if keyword in email_text:
            score += 2
            threats.append(keyword)

    # Suspicious Domains
    suspicious_domains = [
        '.ru',
        '.xyz',
        '.tk',
        'bit.ly',
        'tinyurl',
        'freehosting'
    ]

    for domain in suspicious_domains:
        if domain in email_text:
            score += 3
            threats.append(domain)

    # Detect URLs
    urls = re.findall(r'https?://\S+', email_text)

    if len(urls) > 2:
        score += 2
        threats.append("Too Many Links")

    # Detect Excessive Capitals
    capital_letters = sum(1 for c in request.form['email'] if c.isupper())

    if capital_letters > 40:
        score += 2
        threats.append("Too Many Capital Letters")

    # Detect Excessive Symbols
    exclamations = email_text.count('!')

    if exclamations > 4:
        score += 1
        threats.append("Too Many Exclamation Marks")

    # Detect Fake Urgency
    urgency_words = [
        'immediately',
        'act now',
        'within 24 hours',
        'urgent action required'
    ]

    for word in urgency_words:
        if word in email_text:
            score += 2
            threats.append(word)

    # Risk Calculation
    if score >= 10:
        risk = "High Risk"
        result = "⚠ Dangerous Phishing Email Detected"

    elif score >= 5:
        risk = "Medium Risk"
        result = "⚠ Suspicious Email Detected"

    else:
        risk = "Low Risk"
        result = "✅ Safe Email"

    return render_template(
        'index.html',
        result=result,
        risk=risk,
        threats=threats,
        email_text=request.form['email']
    )

if __name__ == '__main__':
    app.run()