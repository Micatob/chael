import logging
from .base import BaseNormalizer
from models.schema import NormalizedLog, Severity
from typing import Any, Dict, Optional
from datetime import datetime, timezone

logger = logging.getLogger(__name__)


class AWSCloudTrailNormalizer(BaseNormalizer):
    def normalize(self, raw: Dict[str, Any]) -> Optional[NormalizedLog]:
        try:
            detail = raw.get("detail", raw)
            event_name = detail.get("eventName", "")
            event_source = detail.get("eventSource", "")
            user_identity = detail.get("userIdentity", {})
            source_ip = detail.get("sourceIPAddress", "")
            severity = Severity.INFO

            if event_name in ("ConsoleLogin", "AssumeRole"):
                severity = Severity.MEDIUM
            if event_name in ("StopLogging", "DeleteTrail", "UpdateTrail"):
                severity = Severity.CRITICAL
            if event_name in ("CreateKeyPair", "ImportKeyPair", "AuthorizeSecurityGroupIngress"):
                severity = Severity.HIGH
            if event_name in ("RunInstances", "CreateInstance"):
                if detail.get("requestParameters", {}).get("instanceType", "").startswith("p"):
                    severity = Severity.HIGH

            return NormalizedLog(
                timestamp=detail.get("eventTime", datetime.now(timezone.utc).isoformat()),
                host=f"aws:{event_source}",
                source=f"AWS:CloudTrail:{event_source}",
                log_type="cloud",
                severity=severity,
                message=f"AWS {event_name} from {user_identity.get('arn', 'unknown')} "
                        f"via {source_ip}",
                metadata={
                    "cloud_provider": "aws",
                    "event_name": event_name,
                    "event_source": event_source,
                    "aws_region": detail.get("awsRegion", ""),
                    "user_arn": user_identity.get("arn", ""),
                    "source_ip": source_ip,
                    "account_id": detail.get("accountId", ""),
                    "resources": detail.get("resources", []),
                    "raw_event": detail,
                },
            )
        except Exception as e:
            logger.error("Error in AWSCloudTrailNormalizer: %s", e)
            return None


class AzureNormalizer(BaseNormalizer):
    def normalize(self, raw: Dict[str, Any]) -> Optional[NormalizedLog]:
        try:
            detail = raw.get("detail", raw)
            operation_name = detail.get("operationName", {}).get("value", detail.get("operationName", ""))
            status = detail.get("status", {}).get("value", detail.get("status", "Started"))
            caller = detail.get("claims", {}).get("name", detail.get("caller", ""))
            severity = Severity.INFO

            if "Microsoft.Authorization" in operation_name:
                severity = Severity.HIGH
            if "delete" in operation_name.lower() and any(s.lower() in operation_name.lower() for s in ("KeyVault", "Storage", "SQL")):
                severity = Severity.CRITICAL
            if "Microsoft.Security" in operation_name:
                severity = Severity.MEDIUM
            if status == "Failed" and "Authentication" in operation_name:
                severity = Severity.HIGH

            return NormalizedLog(
                timestamp=detail.get("eventTimestamp", datetime.now(timezone.utc).isoformat()),
                host=f"azure:{detail.get('resourceId', 'unknown')}",
                source="Azure:ActivityLog",
                log_type="cloud",
                severity=severity,
                message=f"Azure {operation_name} by {caller} — {status}",
                metadata={
                    "cloud_provider": "azure",
                    "operation_name": operation_name,
                    "status": status,
                    "caller": caller,
                    "resource_id": detail.get("resourceId", ""),
                    "subscription_id": detail.get("subscriptionId", ""),
                    "tenant_id": detail.get("tenantId", ""),
                    "raw_event": detail,
                },
            )
        except Exception as e:
            logger.error("Error in AzureNormalizer: %s", e)
            return None


class GCPNormalizer(BaseNormalizer):
    def normalize(self, raw: Dict[str, Any]) -> Optional[NormalizedLog]:
        try:
            proto = raw.get("protoPayload", raw)
            method = proto.get("methodName", "")
            resource = proto.get("resourceName", "")
            caller = proto.get("caller", "")
            severity = Severity.INFO

            if "SetIamPolicy" in method:
                severity = Severity.HIGH
            if "delete" in method.lower() and any(s.lower() in method.lower() for s in ("Bucket", "Instance", "Cluster")):
                severity = Severity.CRITICAL
            if "create" in method.lower() and "firewall" in method.lower():
                severity = Severity.HIGH
            if proto.get("authenticationInfo", {}).get("principalEmail", "").endswith("@malicious.com"):
                severity = Severity.CRITICAL

            return NormalizedLog(
                timestamp=proto.get("eventTime", datetime.now(timezone.utc).isoformat()),
                host=f"gcp:{resource}",
                source="GCP:AuditLog",
                log_type="cloud",
                severity=severity,
                message=f"GCP {method} by {caller} on {resource}",
                metadata={
                    "cloud_provider": "gcp",
                    "method_name": method,
                    "resource_name": resource,
                    "caller": caller,
                    "resource_type": proto.get("resourceType", ""),
                    "service_name": proto.get("serviceName", ""),
                    "raw_event": raw,
                },
            )
        except Exception as e:
            logger.error("Error in GCPNormalizer: %s", e)
            return None
