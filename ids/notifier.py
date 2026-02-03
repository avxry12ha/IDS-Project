import smtplib
from email.message import EmailMessage
from typing import Optional

from .storage import Alert


class Notifier:
    def __init__(
        self,
        smtp_server: Optional[str],
        smtp_port: int,
        smtp_user: Optional[str],
        smtp_password: Optional[str],
        smtp_recipient: Optional[str],
    ) -> None:
        self.smtp_server = smtp_server
        self.smtp_port = smtp_port
        self.smtp_user = smtp_user
        self.smtp_password = smtp_password
        self.smtp_recipient = smtp_recipient

    def notify(self, alert: Alert) -> None:
        message = (
            f"[{alert.severity}] {alert.alert_type} from {alert.src_ip} to {alert.dst_ip}\n"
            f"Protocol: {alert.protocol}\n"
            f"Details: {alert.details}\n"
            f"Timestamp: {alert.timestamp.isoformat()}"
        )
        print(message)
        if self.smtp_server and self.smtp_recipient:
            self._send_email(alert, message)

    def _send_email(self, alert: Alert, body: str) -> None:
        email_message = EmailMessage()
        email_message["Subject"] = f"IDS Alert: {alert.alert_type}"
        email_message["From"] = self.smtp_user or "ids@localhost"
        email_message["To"] = self.smtp_recipient
        email_message.set_content(body)

        with smtplib.SMTP(self.smtp_server, self.smtp_port) as smtp:
            smtp.starttls()
            if self.smtp_user and self.smtp_password:
                smtp.login(self.smtp_user, self.smtp_password)
            smtp.send_message(email_message)
