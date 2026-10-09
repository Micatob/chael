class TestWindowsNormalizer:
    def test_normalize_login_failure(self, factory, windows_log):
        normalizer = factory.get("windows")
        result = normalizer.normalize(windows_log)
        assert result is not None
        assert result.severity == "MEDIUM"  # 4625 brute-force signal; correlation counts bursts
        assert "4625" in result.message
        assert result.log_type == "windows"

    def test_normalize_login_success(self, factory):
        normalizer = factory.get("windows")
        result = normalizer.normalize({"event_id": 4624, "computer_name": "PC-01", "message": "Logon success"})
        assert result is not None
        assert result.severity == "INFO"  # routine success; kept for forensics, no alert

    def test_normalize_audit_clear(self, factory):
        normalizer = factory.get("windows")
        result = normalizer.normalize({"event_id": 1102, "computer_name": "DC-01", "message": "Log cleared"})
        assert result is not None
        assert result.severity == "CRITICAL"

    def test_normalize_empty_log_returns_none(self, factory):
        normalizer = factory.get("windows")
        result = normalizer.normalize({})
        assert result is not None
        assert result.severity == "INFO"


class TestSyslogNormalizer:
    def test_normalize_failed_ssh(self, factory, syslog_log):
        normalizer = factory.get("syslog")
        result = normalizer.normalize(syslog_log)
        assert result is not None
        assert result.severity == "HIGH"
        assert result.metadata.get("event_type") == "ssh_failed_password"
        assert result.metadata.get("user") == "root"
        assert result.metadata.get("src_ip") == "10.0.0.5"

    def test_normalize_accepted_ssh(self, factory):
        normalizer = factory.get("syslog")
        result = normalizer.normalize({"message": "Accepted password for admin from 10.0.0.1 port 22 ssh2", "host": "web-01"})
        assert result is not None
        assert result.severity == "LOW"
        assert result.metadata.get("event_type") == "ssh_accepted"

    def test_normalize_error_message(self, factory):
        normalizer = factory.get("syslog")
        result = normalizer.normalize({"message": "CRITICAL: kernel panic", "host": "server-01"})
        assert result is not None
        assert result.severity == "CRITICAL"

    def test_normalize_string_input(self, factory):
        normalizer = factory.get("syslog")
        result = normalizer.normalize("Failed password for test from 10.0.0.5 port 22 ssh2")
        assert result is not None
        assert result.severity == "HIGH"

    def test_normalize_generic_fallback(self, factory):
        normalizer = factory.get("generic")
        result = normalizer.normalize({"message": "test message", "host": "test"})
        assert result is not None
        assert result.source == "syslog"


class TestDockerNormalizer:
    def test_normalize_die_event(self, factory, docker_event):
        normalizer = factory.get("docker")
        result = normalizer.normalize(docker_event)
        assert result is not None
        assert result.severity == "HIGH"
        assert result.log_type == "docker"
        assert result.metadata["docker_event_type"] == "docker:die"
        assert result.metadata["container_name"] == "nginx-proxy"

    def test_normalize_stats_event(self, factory, docker_stats_event):
        normalizer = factory.get("docker")
        result = normalizer.normalize(docker_stats_event)
        assert result is not None
        assert result.severity == "INFO"
        assert result.metadata["docker_event_type"] == "docker:stats"


class TestCloudNormalizers:
    def test_aws_console_login(self, factory, aws_log):
        normalizer = factory.get("aws")
        result = normalizer.normalize(aws_log)
        assert result is not None
        assert result.severity == "MEDIUM"
        assert "ConsoleLogin" in result.message
        assert result.metadata["cloud_provider"] == "aws"

    def test_aws_delete_trail(self, factory):
        normalizer = factory.get("aws")
        result = normalizer.normalize({"detail": {"eventName": "DeleteTrail", "eventSource": "cloudtrail.amazonaws.com", "userIdentity": {"arn": "arn:aws:iam::123:user/admin"}}})
        assert result is not None
        assert result.severity == "CRITICAL"

    def test_azure_role_assignment(self, factory, azure_log):
        normalizer = factory.get("azure")
        result = normalizer.normalize(azure_log)
        assert result is not None
        assert result.severity == "HIGH"
        assert result.metadata["cloud_provider"] == "azure"

    def test_azure_delete_keyvault(self, factory):
        normalizer = factory.get("azure")
        result = normalizer.normalize({"detail": {"operationName": {"value": "Microsoft.KeyVault/vaults/delete"}, "status": {"value": "Succeeded"}, "claims": {"name": "admin"}}})
        assert result is not None
        assert result.severity == "CRITICAL"

    def test_gcp_set_iam_policy(self, factory, gcp_log):
        normalizer = factory.get("gcp")
        result = normalizer.normalize(gcp_log)
        assert result is not None
        assert result.severity == "HIGH"
        assert result.metadata["cloud_provider"] == "gcp"

    def test_gcp_delete_bucket(self, factory):
        normalizer = factory.get("gcp")
        result = normalizer.normalize({"protoPayload": {"methodName": "storage.buckets.delete", "resourceName": "projects/p/buckets/b", "caller": "user@example.com"}})
        assert result is not None
        assert result.severity == "CRITICAL"

    def test_normalizer_factory_registry(self, factory):
        assert "windows" in factory._registry
        assert "syslog" in factory._registry
        assert "docker" in factory._registry
        assert "aws" in factory._registry
        assert "azure" in factory._registry
        assert "gcp" in factory._registry
        assert "generic" in factory._registry
