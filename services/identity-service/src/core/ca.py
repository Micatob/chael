import os
import logging
from datetime import datetime, timezone, timedelta
from typing import Optional, Tuple

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

log = logging.getLogger("identity-service.ca")

CA_DIR = "/data/ca"
CA_KEY_FILE = os.path.join(CA_DIR, "ca_key.pem")
CA_CERT_FILE = os.path.join(CA_DIR, "ca_cert.pem")


class CertificateAuthority:
    def __init__(self, ca_dir: str = CA_DIR):
        self.ca_dir = ca_dir
        self._ca_key = None
        self._ca_cert = None
        self._ensure_ca()

    def _ensure_ca(self):
        os.makedirs(self.ca_dir, exist_ok=True)
        if os.path.exists(CA_KEY_FILE) and os.path.exists(CA_CERT_FILE):
            self._load_ca()
            log.info("Loaded existing CA from %s", self.ca_dir)
        else:
            self._generate_ca()
            log.info("Generated new CA in %s", self.ca_dir)

    def _load_ca(self):
        with open(CA_KEY_FILE, "rb") as f:
            self._ca_key = serialization.load_pem_private_key(
                f.read(), password=None, backend=default_backend()
            )
        with open(CA_CERT_FILE, "rb") as f:
            self._ca_cert = x509.load_pem_x509_certificate(f.read(), backend=default_backend())

    def _generate_ca(self):
        key = rsa.generate_private_key(
            public_exponent=65537, key_size=4096, backend=default_backend()
        )
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "XX"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Chael SIEM"),
            x509.NameAttribute(NameOID.COMMON_NAME, "Chael SIEM Root CA"),
        ])
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.now(timezone.utc))
            .not_valid_after(datetime.now(timezone.utc) + timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(key, hashes.SHA256(), backend=default_backend())
        )
        with open(CA_KEY_FILE, "wb") as f:
            f.write(key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            ))
        os.chmod(CA_KEY_FILE, 0o600)
        with open(CA_CERT_FILE, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
        self._ca_key = key
        self._ca_cert = cert

    def sign_agent_cert(
        self, machine_id: str, hostname: str, public_key_pem: str,
        valid_days: int = 365,
    ) -> Tuple[str, str]:
        public_key = serialization.load_pem_public_key(
            public_key_pem.encode(), backend=default_backend()
        )
        now = datetime.now(timezone.utc)
        cert = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([
                x509.NameAttribute(NameOID.COUNTRY_NAME, "XX"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Chael SIEM"),
                x509.NameAttribute(NameOID.COMMON_NAME, f"agent:{machine_id}"),
                x509.NameAttribute(NameOID.DOMAIN_COMPONENT, hostname),
            ]))
            .issuer_name(self._ca_cert.subject)
            .public_key(public_key)
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + timedelta(days=valid_days))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(
                x509.SubjectAlternativeName([x509.DNSName(hostname)]),
                critical=False,
            )
            .sign(self._ca_key, hashes.SHA256(), backend=default_backend())
        )
        cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
        return cert_pem, self._ca_cert.public_bytes(serialization.Encoding.PEM).decode()

    def get_ca_cert_pem(self) -> str:
        return self._ca_cert.public_bytes(serialization.Encoding.PEM).decode()
