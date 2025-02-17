# routes/send_email.py

import smtplib
from email.mime.text import MIMEText
from config import Config

def send_email(to, subject, body):
    msg = MIMEText(body)
    msg['Subject'] = subject
    msg['From'] = Config.EMAIL_USER
    msg['To'] = to
    try:
        with smtplib.SMTP(Config.EMAIL_HOST, Config.EMAIL_PORT) as server:
            server.starttls()
            server.login(Config.EMAIL_USER, Config.EMAIL_PASSWORD)
            server.sendmail(Config.EMAIL_USER, [to], msg.as_string())
    except Exception as e:
        print(f"Error sending email to {to}: {str(e)}")
