"""Creación y validación de una CA local y certificados X.509."""

from datetime import datetime, timedelta, timezone
from pathlib import Path
import re

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import NameOID

from .crypto_utils import generate_rsa_private_key


def validate_identity(identity: str) -> str:
    identity = identity.strip()
    if not re.fullmatch(r"[A-Za-z0-9_.@-]{1,64}", identity):
        raise ValueError("La identidad debe tener 1-64 caracteres: letras, números, . _ @ -.")
    return identity


def _write_private_key(path: Path, key: rsa.RSAPrivateKey) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ))
    try:
        path.chmod(0o600)
    except OSError:
        pass


def _read_private_key(path: Path) -> rsa.RSAPrivateKey:
    key = serialization.load_pem_private_key(path.read_bytes(), password=None)
    if not isinstance(key, rsa.RSAPrivateKey):
        raise ValueError(f"La clave en {path} no es RSA.")
    return key


def load_certificate(path: Path) -> x509.Certificate:
    return x509.load_pem_x509_certificate(path.read_bytes())


def init_ca(root: Path, name: str = "Taller Criptografia CA") -> None:
    ca_dir = root / "ca"
    key_path, cert_path = ca_dir / "ca_key.pem", ca_dir / "ca_cert.pem"
    if key_path.exists() or cert_path.exists():
        raise FileExistsError("La CA ya existe; no se sobrescribió.")
    key = generate_rsa_private_key()
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject).issuer_name(subject).public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1)).not_valid_after(now + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(x509.KeyUsage(
            digital_signature=True, content_commitment=False, key_encipherment=False,
            data_encipherment=False, key_agreement=False, key_cert_sign=True,
            crl_sign=True, encipher_only=None, decipher_only=None,
        ), critical=True)
        .sign(key, hashes.SHA256())
    )
    _write_private_key(key_path, key)
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))


def issue_user(root: Path, identity: str, validity_days: int = 365) -> None:
    identity = validate_identity(identity)
    if not 1 <= validity_days <= 3650:
        raise ValueError("La vigencia debe estar entre 1 y 3650 días.")
    user_dir = root / "users" / identity
    key_path, cert_path = user_dir / "private_key.pem", user_dir / "certificate.pem"
    if key_path.exists() or cert_path.exists():
        raise FileExistsError(f"El usuario {identity} ya existe; no se sobrescribió.")
    ca_key = _read_private_key(root / "ca" / "ca_key.pem")
    ca_cert = load_certificate(root / "ca" / "ca_cert.pem")
    key = generate_rsa_private_key()
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, identity)])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject).issuer_name(ca_cert.subject).public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1)).not_valid_after(now + timedelta(days=validity_days))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(
            digital_signature=True, content_commitment=True, key_encipherment=True,
            data_encipherment=False, key_agreement=False, key_cert_sign=False,
            crl_sign=False, encipher_only=None, decipher_only=None,
        ), critical=True)
        .add_extension(x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.EMAIL_PROTECTION]), critical=False)
        .sign(ca_key, hashes.SHA256())
    )
    _write_private_key(key_path, key)
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))


def validate_certificate(cert: x509.Certificate, ca_cert: x509.Certificate, expected_identity: str) -> None:
    expected_identity = validate_identity(expected_identity)
    if cert.issuer != ca_cert.subject:
        raise ValueError("Certificado inválido: emisor distinto de la CA de confianza.")
    try:
        constraints = ca_cert.extensions.get_extension_for_class(x509.BasicConstraints).value
        if not constraints.ca:
            raise ValueError("El certificado de confianza no es una CA.")
        cert.public_key().public_numbers()  # Fuerza a comprobar que exista una clave pública RSA.
        ca_cert.public_key().verify(cert.signature, cert.tbs_certificate_bytes, padding.PKCS1v15(), cert.signature_hash_algorithm)
    except ValueError:
        raise
    except Exception as exc:
        raise ValueError("Certificado inválido: firma de la CA incorrecta.") from exc
    now = datetime.now(timezone.utc)
    not_before = cert.not_valid_before_utc
    not_after = cert.not_valid_after_utc
    if now < not_before or now > not_after:
        raise ValueError("Certificado inválido: está fuera de su periodo de vigencia.")
    try:
        actual_identity = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    except IndexError as exc:
        raise ValueError("Certificado inválido: no contiene una identidad (CN).") from exc
    if actual_identity != expected_identity:
        raise ValueError(f"Certificado inválido: identidad esperada {expected_identity}, recibida {actual_identity}.")
    if not isinstance(cert.public_key(), rsa.RSAPublicKey):
        raise ValueError("Certificado inválido: se esperaba una clave pública RSA.")
