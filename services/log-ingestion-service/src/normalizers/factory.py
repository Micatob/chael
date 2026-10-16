from .real_world import WindowsNormalizer, SyslogNormalizer, DockerNormalizer, GenericJSONNormalizer, CEFNormalizer
from .vscode_ci import VSCodeNormalizer, CINormalizer
from .cloud import AWSCloudTrailNormalizer, AzureNormalizer, GCPNormalizer
from .web_server import ApacheAccessNormalizer, NginxAccessNormalizer, WebErrorNormalizer
from typing import Dict, Optional, Any

class NormalizerFactory:
    _registry = {
        "windows": WindowsNormalizer(),
        "syslog": SyslogNormalizer(),
        "docker": DockerNormalizer(),
        "aws": AWSCloudTrailNormalizer(),
        "azure": AzureNormalizer(),
        "gcp": GCPNormalizer(),
        "apache": ApacheAccessNormalizer(),
        "nginx": NginxAccessNormalizer(),
        "web_error": WebErrorNormalizer(),
        "generic": SyslogNormalizer(),
        "json": GenericJSONNormalizer(),
        "generic_json": GenericJSONNormalizer(),
        "cef": CEFNormalizer(),
        "vscode": VSCodeNormalizer(),
        "ci": CINormalizer(),
    }

    @classmethod
    def get(cls, source_type: str = "generic"):
        return cls._registry.get(source_type.lower(), cls._registry["generic"])
