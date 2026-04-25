import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import time


def send_alert_emails(sender_email, sender_password, pending_emails):
    """
    Send all queued alert emails over a SINGLE SMTP connection, one by one.

    Parameters
    ----------
    sender_email    : str   - Gmail sender address
    sender_password : str   - Gmail App Password
    pending_emails  : list  - each item is a dict with keys:
                              recipient_emails, device_ip, old_status, new_status
    """
    if not pending_emails:
        return

    print(f"📨 Connecting to SMTP — sending {len(pending_emails)} emails sequentially...")

    try:
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        server.login(sender_email, sender_password)
        print("✅ SMTP connection established")

        for idx, item in enumerate(pending_emails):
            device_ip      = item['device_ip']
            old_status     = item['old_status']
            new_status     = item['new_status']
            recipients     = item['recipient_emails']

            subject = f"Network Alert: {device_ip} is {new_status}"
            body = f"""
NETWORK MONITOR ALERT

Device IP  : {device_ip}
Old Status : {old_status}
New Status : {new_status}

Please check the device immediately if it is down.

***
This is an automated alert from Network Monitor.
"""
            for recipient in recipients:
                if not recipient:
                    continue
                try:
                    msg = MIMEMultipart()
                    msg['From']    = sender_email
                    msg['To']      = recipient
                    msg['Subject'] = subject
                    msg.attach(MIMEText(body, 'plain'))
                    server.sendmail(sender_email, recipient, msg.as_string())
                    print(f"  ✉️  Sent [{new_status}] alert for {device_ip} → {recipient}")
                except Exception as e:
                    print(f"  ❌ Failed to send to {recipient}: {e}")

            # Add delay between emails to avoid hitting Gmail rate limits
            # Delay after each email except the last one
            if idx < len(pending_emails) - 1:
                delay_seconds = 2
                print(f"  ⏳ Waiting {delay_seconds}s before next email...")
                time.sleep(delay_seconds)

        server.quit()
        print("📭 SMTP connection closed")

    except Exception as e:
        print(f"❌ SMTP Error: {e}")
