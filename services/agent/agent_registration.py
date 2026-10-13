import os
import json
import hashlib
import hmac
import secrets
import uuid
import socket
import platform
import logging
from pathlib import Path
from typing import Optional, Tuple
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
from datetime import datetime, timezone

log = logging.getLogger("chael-agent.registration")

CONFIG_DIR = Path.home() / ".chael" / "agent"
CONFIG_FILE = CONFIG_DIR / "agent_config.json"
KEY_FILE = CONFIG_DIR / "private_key.pem"
CONFIG_KEY_FILE = CONFIG_DIR / ".config_key"


def _generate_machine_id() -> str:
    parts = [
        socket.gethostname(),
        str(uuid.getnode()),
        platform.machine(),
        platform.processor() or "",
    ]
    raw = ":".join(parts).encode()
    return hashlib.sha256(raw).hexdigest()[:32]


def _generate_key_pair() -> Tuple[bytes, bytes]:
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend(),
    )
    private_bytes = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_bytes = key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return private_bytes, public_bytes


def _encrypt_config(data: dict, key: bytes) -> bytes:
    f = Fernet(key)
    return f.encrypt(json.dumps(data).encode())


def _decrypt_config(data: bytes, key: bytes) -> dict:
    f = Fernet(key)
    return json.loads(f.decrypt(data).decode())


def _load_or_create_config_key() -> bytes:
    if CONFIG_KEY_FILE.exists():
        return CONFIG_KEY_FILE.read_bytes()
    key = Fernet.generate_key()
    CONFIG_KEY_FILE.parent.mkdir(parents=True, exist_ok=True)
    CONFIG_KEY_FILE.write_bytes(key)
    os.chmod(str(CONFIG_KEY_FILE), 0o600)
    return key


def load_agent_config() -> Optional[dict]:
    if not CONFIG_FILE.exists():
        return None
    try:
        key = _load_or_create_config_key()
        encrypted = CONFIG_FILE.read_bytes()
        return _decrypt_config(encrypted, key)
    except Exception as e:
        log.error("Failed to load encrypted agent config: %s", e)
        return None


def save_agent_config(config: dict):
    key = _load_or_create_config_key()
    encrypted = _encrypt_config(config, key)
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    CONFIG_FILE.write_bytes(encrypted)
    os.chmod(str(CONFIG_FILE), 0o600)
    log.info("Agent config saved securely to %s", CONFIG_FILE)


def get_or_create_machine_identity() -> Tuple[str, bytes]:
    config = load_agent_config()
    if config and "machine_id" in config and "private_key_pem" in config:
        machine_id = config["machine_id"]
        private_pem = config["private_key_pem"].encode()
        return machine_id, private_pem

    machine_id = _generate_machine_id()
    private_pem, public_pem = _generate_key_pair()

    config = {
        "machine_id": machine_id,
        "private_key_pem": private_pem.decode(),
        "public_key_pem": public_pem.decode(),
        "created_at": datetime.now(timezone.utc).isoformat(),
        "hostname": socket.gethostname(),
        "platform": platform.system(),
    }
    save_agent_config(config)
    return machine_id, private_pem


def get_public_key_pem() -> Optional[str]:
    config = load_agent_config()
    if config:
        return config.get("public_key_pem")
    return None


def sign_payload(payload: bytes, private_key_pem: bytes) -> str:
    from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
    private_key = serialization.load_pem_private_key(
        private_key_pem, password=None, backend=default_backend()
    )
    # RSA-PSS with SHA-256 (cryptography requires explicit padding; the old
    # call passed none and raised TypeError, breaking the mTLS path entirely).
    signature = private_key.sign(
        payload,
        asym_padding.PSS(
            mgf=asym_padding.MGF1(hashes.SHA256()),
            salt_length=asym_padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )
    return signature.hex()


def verify_payload_signature(payload: bytes, signature_hex: str, public_key_pem: str) -> bool:
    """Verify an RSA-PSS/SHA-256 signature. Returns False on any failure."""
    try:
        from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
        from cryptography.exceptions import InvalidSignature
        public_key = serialization.load_pem_public_key(
            public_key_pem.encode(), backend=default_backend()
        )
        public_key.verify(
            bytes.fromhex(signature_hex),
            payload,
            asym_padding.PSS(
                mgf=asym_padding.MGF1(hashes.SHA256()),
                salt_length=asym_padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
        return True
    except Exception:
        return False


def compute_hmac(payload: bytes, api_key: str) -> str:
    return hmac.new(
        api_key.encode(), payload, hashlib.sha256
    ).hexdigest()


def build_registration_payload() -> dict:
    machine_id, private_pem = get_or_create_machine_identity()
    public_pem = get_public_key_pem()
    hostname = socket.gethostname()
    reg_data = {
        "machine_id": machine_id,
        "hostname": hostname,
        "platform": platform.system(),
        "platform_version": platform.version(),
        "os_info": f"{platform.system()} {platform.release()}",
        "public_key": public_pem,
        "agent_version": os.environ.get("CHAEL_AGENT_VERSION", "1.0.0"),
    }
    signature = sign_payload(
        json.dumps(reg_data, sort_keys=True).encode(),
        private_pem,
    )
    reg_data["signature"] = signature
    return reg_data
