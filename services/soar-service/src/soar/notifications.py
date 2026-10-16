"""
Notification service for SOAR automated actions.
Supports email, webhook, and SIEM notification channels.
"""
import os
import smtplib
import json
import logging
import requests
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone
from dataclasses import dataclass, field
from enum import Enum

try:
    from opensearchpy import OpenSearch
    HAS_OPENSEARCH = True
except ImportError:
    HAS_OPENSEARCH = False

from config import settings

logger = logging.getLogger(__name__)


class NotificationChannel(str, Enum):
    EMAIL = "email"
    WEBHOOK = "webhook"
    SIEM = "siem"
    SLACK = "slack"
    TELEGRAM = "telegram"


class NotificationPriority(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class NotificationConfig:
    """Configuration for a notification channel."""

    def __init__(
        self,
        channel: NotificationChannel,
        enabled: bool = True,
        config: Dict[str, Any] = None,
    ):
        self.channel = channel
        self.enabled = enabled
        self.config = config or {}

    def validate(self) -> bool:
        """Validate that required config fields are present."""
        if self.channel == NotificationChannel.EMAIL:
            required = ["smtp_host", "smtp_port", "from_addr", "to_addrs"]
            missing = [r for r in required if r not in self.config]
            if missing:
                raise ValueError(f"Email config missing required fields: {missing}")
        elif self.channel == NotificationChannel.WEBHOOK:
            if "url" not in self.config:
                raise ValueError("Webhook config missing 'url'")
        elif self.channel == NotificationChannel.SLACK:
            if "webhook_url" not in self.config:
                raise ValueError("Slack config missing 'webhook_url'")
        elif self.channel == NotificationChannel.TELEGRAM:
            missing = [r for r in ("bot_token", "chat_id") if r not in self.config]
            if missing:
                raise ValueError(f"Telegram config missing required fields: {missing}")
        return True


class NotificationRequest:
    """A notification to be sent."""

    def __init__(
        self,
        channel: NotificationChannel,
        title: str,
        message: str,
        priority: NotificationPriority = NotificationPriority.MEDIUM,
        incident_id: Optional[str] = None,
        action_name: Optional[str] = None,
        action_status: Optional[str] = None,
        metadata: Dict[str, Any] = None,
        timestamp: datetime = None,
    ):
        self.channel = channel
        self.title = title
        self.message = message
        self.priority = priority
        self.incident_id = incident_id
        self.action_name = action_name
        self.action_status = action_status
        self.metadata = metadata or {}
        self.timestamp = timestamp or datetime.now(timezone.utc)


class NotificationResult:
    """Result of a notification attempt."""

    def __init__(
        self,
        success: bool,
        channel: NotificationChannel,
        message_id: Optional[str] = None,
        error: Optional[str] = None,
        timestamp: datetime = None,
    ):
        self.success = success
        self.channel = channel
        self.message_id = message_id
        self.error = error
        self.timestamp = timestamp or datetime.now(timezone.utc)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "success": self.success,
            "channel": self.channel.value,
            "message_id": self.message_id,
            "error": self.error,
            "timestamp": self.timestamp.isoformat(),
        }


@dataclass
class NotificationService:
    """
    Notification service that dispatches notifications across multiple channels.
    Integrates with the SOAR engine to notify stakeholders of automated actions.
    """

    configs: Dict[NotificationChannel, NotificationConfig] = field(default_factory=dict)
    _opensearch_client: Optional[object] = None

    def __post_init__(self):
        if HAS_OPENSEARCH:
            self._opensearch_client = self._init_opensearch()

    def _init_opensearch(self):
        """Initialize OpenSearch client for SIEM notifications and audit logging."""
        try:
            client = OpenSearch(
                hosts=[
                    {
                        "host": settings.OPENSEARCH_HOST,
                        "port": settings.OPENSEARCH_PORT,
                    }
                ],
                http_auth=(settings.OPENSEARCH_USER, settings.OPENSEARCH_PASSWORD),
                use_ssl=settings.OPENSEARCH_USE_SSL,
                verify_certs=settings.OPENSEARCH_VERIFY_CERTS,
                ssl_assert_hostname=False,
                ssl_show_warn=False,
            )
            return client
        except Exception as e:
            logger.warning("Failed to initialize OpenSearch client: %s", e)
            return None

    def register_config(self, config: NotificationConfig) -> None:
        """Register or update a notification channel configuration."""
        config.validate()
        self.configs[config.channel] = config
        logger.info("Registered notification config for channel: %s", config.channel)

    def get_config(self, channel: NotificationChannel) -> Optional[NotificationConfig]:
        """Get configuration for a specific channel."""
        return self.configs.get(channel)

    def send_notification(self, request: NotificationRequest) -> NotificationResult:
        """Send a notification via the specified channel."""
        config = self.configs.get(request.channel)
        if not config:
            return NotificationResult(
                success=False,
                channel=request.channel,
                error=f"No configuration found for channel: {request.channel}",
            )
        if not config.enabled:
            return NotificationResult(
                success=False,
                channel=request.channel,
                error=f"Channel disabled: {request.channel}",
            )

        try:
            if request.channel == NotificationChannel.EMAIL:
                return self._send_email(request, config)
            elif request.channel == NotificationChannel.WEBHOOK:
                return self._send_webhook(request, config)
            elif request.channel == NotificationChannel.SIEM:
                return self._send_siem(request, config)
            elif request.channel == NotificationChannel.SLACK:
                return self._send_slack(request, config)
            elif request.channel == NotificationChannel.TELEGRAM:
                return self._send_telegram(request, config)
            else:
                return NotificationResult(
                    success=False,
                    channel=request.channel,
                    error=f"Unsupported channel: {request.channel}",
                )
        except Exception as e:
            logger.error("Failed to send notification via %s: %s", request.channel, e, exc_info=True)
            return NotificationResult(
                success=False,
                channel=request.channel,
                error=str(e),
            )

    def send_bulk(self, requests: List[NotificationRequest]) -> List[NotificationResult]:
        """Send multiple notifications, returning results for each."""
        results = []
        for req in requests:
            result = self.send_notification(req)
            results.append(result)
        return results

    def _send_email(self, request: NotificationRequest, config: NotificationConfig) -> NotificationResult:
        """Send notification via email using SMTP."""
        email_config = config.config
        smtp_host = email_config["smtp_host"]
        smtp_port = email_config.get("smtp_port", 587)
        from_addr = email_config["from_addr"]
        to_addrs = email_config["to_addrs"]
        use_tls = email_config.get("use_tls", True)
        smtp_user = email_config.get("smtp_user")
        smtp_password = email_config.get("smtp_password")

        subject = f"[SOAR] {request.priority.value.upper()}: {request.title}"
        if request.incident_id:
            subject += f" [Incident: {request.incident_id[:8]}]"

        body = self._format_email_body(request)

        msg = MIMEMultipart()
        msg["From"] = from_addr
        msg["To"] = ", ".join(to_addrs)
        msg["Subject"] = subject
        msg.attach(MIMEText(body, "plain"))

        try:
            with smtplib.SMTP(smtp_host, smtp_port, timeout=10) as server:
                if use_tls:
                    server.starttls()
                if smtp_user and smtp_password:
                    server.login(smtp_user, smtp_password)
                server.sendmail(from_addr, to_addrs, msg.as_string())

            logger.info("Email notification sent for incident %s", request.incident_id)
            return NotificationResult(
                success=True,
                channel=request.channel,
                message_id=f"email-{request.incident_id}-{datetime.now(timezone.utc).timestamp()}",
            )
        except smtplib.SMTPException as e:
            logger.error("SMTP error: %s", e, exc_info=True)
            raise

    def _send_webhook(self, request: NotificationRequest, config: NotificationConfig) -> NotificationResult:
        """Send notification via HTTP webhook."""
        webhook_config = config.config
        url = webhook_config["url"]
        headers = webhook_config.get("headers", {"Content-Type": "application/json"})
        timeout = webhook_config.get("timeout", 30)

        payload = {
            "title": request.title,
            "message": request.message,
            "priority": request.priority.value,
            "incident_id": request.incident_id,
            "action_name": request.action_name,
            "action_status": request.action_status,
            "metadata": request.metadata,
            "timestamp": request.timestamp.isoformat(),
        }

        response = requests.post(url, json=payload, headers=headers, timeout=timeout)
        response.raise_for_status()

        logger.info("Webhook notification sent to %s for incident %s", url, request.incident_id)
        return NotificationResult(
            success=True,
            channel=request.channel,
            message_id=f"webhook-{request.incident_id}-{datetime.now(timezone.utc).timestamp()}",
        )

    def _send_siem(self, request: NotificationRequest, config: NotificationConfig) -> NotificationResult:
        """Index notification event into OpenSearch for SIEM integration."""
        if not self._opensearch_client:
            raise RuntimeError("OpenSearch client not initialized")

        siem_config = config.config
        index_name = siem_config.get("index_name", "soar-notifications")

        doc = {
            "timestamp": request.timestamp.isoformat(),
            "channel": request.channel.value,
            "title": request.title,
            "message": request.message,
            "priority": request.priority.value,
            "incident_id": request.incident_id,
            "action_name": request.action_name,
            "action_status": request.action_status,
            "metadata": request.metadata,
            "type": "soar_automated_action",
        }

        self._opensearch_client.index(
            index=index_name,
            body=doc,
            id=f"soar-{request.incident_id}-{datetime.now(timezone.utc).timestamp()}",
        )

        logger.info("SIEM notification indexed to %s for incident %s", index_name, request.incident_id)
        return NotificationResult(
            success=True,
            channel=request.channel,
            message_id=f"siem-{request.incident_id}-{datetime.now(timezone.utc).timestamp()}",
        )

    def _send_telegram(self, request: NotificationRequest, config: NotificationConfig) -> NotificationResult:
        bot_token = config.config.get("bot_token", os.environ.get("TELEGRAM_BOT_TOKEN", ""))
        chat_id = config.config.get("chat_id", os.environ.get("TELEGRAM_CHAT_ID", ""))
        if not bot_token or not chat_id:
            return NotificationResult(
                success=False,
                channel=request.channel,
                error="TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID must be set",
            )

        priority_icon = {
            NotificationPriority.LOW: "\U0001f7e2",
            NotificationPriority.MEDIUM: "\U0001f7e1",
            NotificationPriority.HIGH: "\U0001f7e0",
            NotificationPriority.CRITICAL: "\U0001f534",
        }
        icon = priority_icon.get(request.priority, "\u26ab")

        text = (
            f"{icon} <b>[{request.priority.value.upper()}] {request.title}</b>\n\n"
            f"<b>Incident:</b> <code>{request.incident_id or 'N/A'}</code>\n"
            f"<b>Action:</b> {request.action_name or 'N/A'}\n"
            f"<b>Status:</b> {request.action_status or 'N/A'}\n\n"
            f"{request.message[:3000]}"
        )

        try:
            resp = requests.post(
                f"https://api.telegram.org/bot{bot_token}/sendMessage",
                json={
                    "chat_id": chat_id,
                    "text": text,
                    "parse_mode": "HTML",
                },
                timeout=15,
            )
            resp.raise_for_status()
            data = resp.json()
            message_id = f"telegram-{data.get('result', {}).get('message_id', 'unknown')}"
            logger.info("Telegram notification sent for incident %s", request.incident_id)
            return NotificationResult(success=True, channel=request.channel, message_id=message_id)
        except Exception as e:
            logger.error("Telegram notification failed: %s", e, exc_info=True)
            return NotificationResult(
                success=False, channel=request.channel, error=str(e),
            )

    def _send_slack(self, request: NotificationRequest, config: NotificationConfig) -> NotificationResult:
        """Send notification via Slack webhook."""
        slack_config = config.config
        webhook_url = slack_config["webhook_url"]

        priority_emoji = {
            NotificationPriority.LOW: ":large_green_circle:",
            NotificationPriority.MEDIUM: ":large_yellow_circle:",
            NotificationPriority.HIGH: ":large_orange_circle:",
            NotificationPriority.CRITICAL: ":red_circle:",
        }
        emoji = priority_emoji.get(request.priority, ":white_circle:")

        payload = {
            "text": f"{emoji} *[{request.priority.value.upper()}]* {request.title}",
            "blocks": [
                {
                    "type": "header",
                    "text": {"type": "plain_text", "text": f"{emoji} SOAR Action Notification"},
                },
                {
                    "type": "section",
                    "fields": [
                        {"type": "mrkdwn", "text": f"*Title:*\n{request.title}"},
                        {"type": "mrkdwn", "text": f"*Priority:*\n{request.priority.value.upper()}"},
                        {"type": "mrkdwn", "text": f"*Incident:*\n`{request.incident_id or 'N/A'}`"},
                        {"type": "mrkdwn", "text": f"*Action:*\n{request.action_name or 'N/A'}"},
                        {"type": "mrkdwn", "text": f"*Status:*\n{request.action_status or 'N/A'}"},
                    ],
                },
                {
                    "type": "section",
                    "text": {"type": "mrkdwn", "text": f"*Details:*\n{request.message}"},
                },
            ],
        }

        response = requests.post(webhook_url, json=payload, timeout=30)
        response.raise_for_status()

        logger.info("Slack notification sent for incident %s", request.incident_id)
        return NotificationResult(
            success=True,
            channel=request.channel,
            message_id=f"slack-{request.incident_id}-{datetime.now(timezone.utc).timestamp()}",
        )

    def _format_email_body(self, request: NotificationRequest) -> str:
        """Format notification details into an email body."""
        lines = [
            f"SOAR Automated Action Notification",
            f"{'=' * 40}",
            f"",
            f"Title: {request.title}",
            f"Priority: {request.priority.value.upper()}",
            f"Timestamp: {request.timestamp.isoformat()}",
            f"",
            f"Message:",
            f"{request.message}",
            f"",
        ]
        if request.incident_id:
            lines.append(f"Incident ID: {request.incident_id}")
        if request.action_name:
            lines.append(f"Action: {request.action_name}")
        if request.action_status:
            lines.append(f"Action Status: {request.action_status}")
        if request.metadata:
            lines.append(f"")
            lines.append("Additional Details:")
            for key, value in request.metadata.items():
                lines.append(f"  {key}: {value}")
        lines.append("")
        lines.append("---")
        lines.append("This is an automated message from the Chael SIEM SOAR engine.")
        return "\n".join(lines)

    def notify_action_executed(
        self,
        action_name: str,
        action_result: Dict[str, Any],
        incident: Any,
        priority: NotificationPriority = None,
    ) -> List[NotificationResult]:
        """
        Convenience method to send notifications for a completed SOAR action.
        Sends to all configured channels.
        """
        action_id = action_result.get("action_id", "unknown")
        status = action_result.get("status", "unknown")

        if priority is None:
            priority = NotificationPriority.HIGH if status == "EXECUTED" else NotificationPriority.MEDIUM

        title = f"Action Executed: {action_name}"
        message = (
            f"Automated SOAR action '{action_name}' has been executed for incident "
            f"{incident.incident_id}.\n\n"
            f"Status: {status}\n"
            f"Action ID: {action_id}\n"
            f"Description: {incident.description or 'N/A'}\n"
            f"Risk Score: {incident.risk_score}"
        )

        metadata = {
            "action_id": action_id,
            "action_name": action_name,
            "status": status,
            "risk_score": incident.risk_score,
            "artifacts": json.dumps(incident.artifacts, default=str),
        }

        requests_to_send = []
        for channel in self.configs:
            if self.configs[channel].enabled:
                requests_to_send.append(
                    NotificationRequest(
                        channel=channel,
                        title=title,
                        message=message,
                        priority=priority,
                        incident_id=incident.incident_id,
                        action_name=action_name,
                        action_status=status,
                        metadata=metadata,
                    )
                )

        return self.send_bulk(requests_to_send)


# Global notification service instance
notification_service = NotificationService()