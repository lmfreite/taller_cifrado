"""Interfaz web local para la demostración del taller."""

import json
import os
from pathlib import Path
from datetime import datetime, timedelta, timezone
from typing import Literal
from uuid import UUID, uuid4
import hashlib

from cryptography import x509
from cryptography.exceptions import InvalidSignature, InvalidTag
from fastapi import FastAPI, HTTPException, Response
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.x509.oid import NameOID

from .certificates import _read_private_key, init_ca, issue_user, load_certificate, validate_certificate, validate_identity
from .crypto_utils import b64e, generate_rsa_private_key, rsa_oaep_decrypt, rsa_oaep_encrypt, sign
from .hashing import avalanche_demo
from .messaging import receive_message, send_message, simulate_unauthorized_unwrap

DATA_DIR = Path(os.environ.get("SECUREMSG_DATA", "data"))
PKI_DIR = DATA_DIR / "pki"
MESSAGES_DIR = DATA_DIR / "messages"
INDEX_FILE = Path(__file__).parent / "static" / "index.html"

app = FastAPI(title="Taller de mensajería segura", docs_url=None, redoc_url=None)


class CaRequest(BaseModel):
    name: str = Field(default="Taller Criptografia CA", min_length=1, max_length=100)


class UserRequest(BaseModel):
    identity: str = Field(min_length=1, max_length=64)
    days: int = Field(default=365, ge=1, le=3650)


class SendRequest(BaseModel):
    sender: str = Field(min_length=1, max_length=64)
    recipient: str = Field(min_length=1, max_length=64)
    message: str = Field(min_length=1, max_length=10000)


class ReceiveRequest(BaseModel):
    recipient: str = Field(min_length=1, max_length=64)
    expected_sender: str | None = Field(default=None, max_length=64)


class InterceptRequest(BaseModel):
    identity: str = Field(min_length=1, max_length=64)


class LabTextRequest(BaseModel):
    message: str = Field(min_length=1, max_length=10000)


class InvalidCertificateRequest(BaseModel):
    scenario: Literal["untrusted", "expired"]


def _users() -> list[str]:
    users_dir = PKI_DIR / "users"
    if not users_dir.exists():
        return []
    return sorted(path.name for path in users_dir.iterdir() if path.is_dir() and (path / "certificate.pem").is_file())


def _message_path(message_id: str) -> Path:
    try:
        safe_id = str(UUID(message_id))
    except ValueError as exc:
        raise HTTPException(status_code=404, detail="Mensaje no encontrado.") from exc
    path = MESSAGES_DIR / f"{safe_id}.json"
    if not path.is_file():
        raise HTTPException(status_code=404, detail="Mensaje no encontrado.")
    return path


@app.get("/", include_in_schema=False)
def home() -> FileResponse:
    return FileResponse(INDEX_FILE)


@app.get("/api/state")
def state() -> dict:
    return {
        "ca_initialized": (PKI_DIR / "ca" / "ca_cert.pem").is_file() and (PKI_DIR / "ca" / "ca_key.pem").is_file(),
        "users": _users(),
    }


@app.post("/api/ca")
def create_ca(request: CaRequest) -> dict:
    try:
        init_ca(PKI_DIR, request.name.strip())
        return {"message": "Autoridad certificadora creada."}
    except (ValueError, FileExistsError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/api/users")
def create_user(request: UserRequest) -> dict:
    try:
        identity = validate_identity(request.identity)
        issue_user(PKI_DIR, identity, request.days)
        return {"message": f"Usuario {identity} registrado."}
    except (ValueError, FileNotFoundError, FileExistsError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.get("/api/users/{identity}/credentials")
def user_credentials(identity: str, response: Response) -> dict:
    response.headers["Cache-Control"] = "no-store, max-age=0"
    response.headers["Pragma"] = "no-cache"
    try:
        identity = validate_identity(identity)
        if identity not in _users():
            raise HTTPException(status_code=404, detail="Usuario no encontrado.")
        user_dir = PKI_DIR / "users" / identity
        ca_cert = load_certificate(PKI_DIR / "ca" / "ca_cert.pem")
        cert = load_certificate(user_dir / "certificate.pem")
        validate_certificate(cert, ca_cert, identity)
        private_key = _read_private_key(user_dir / "private_key.pem")
        if private_key.public_key().public_numbers() != cert.public_key().public_numbers():
            raise ValueError("La clave privada no corresponde al certificado.")
        public_pem = cert.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode("ascii")
        return {
            "identity": identity,
            "rsa_key_size": private_key.key_size,
            "private_key_pem": (user_dir / "private_key.pem").read_text(encoding="ascii"),
            "public_key_pem": public_pem,
            "certificate_pem": cert.public_bytes(serialization.Encoding.PEM).decode("ascii"),
            "certificate_subject": cert.subject.rfc4514_string(),
            "certificate_issuer": cert.issuer.rfc4514_string(),
            "certificate_valid_from_utc": cert.not_valid_before_utc.isoformat(),
            "certificate_valid_until_utc": cert.not_valid_after_utc.isoformat(),
            "certificate_sha256_fingerprint": cert.fingerprint(hashes.SHA256()).hex(),
            "certificate_signature_valid": True,
        }
    except HTTPException:
        raise
    except (ValueError, FileNotFoundError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/api/messages")
def send(request: SendRequest) -> dict:
    message_id = str(uuid4())
    output = MESSAGES_DIR / f"{message_id}.json"
    try:
        trace = send_message(PKI_DIR, request.sender, request.recipient, request.message, output)
        return {"id": message_id, "message": "Mensaje firmado y cifrado.", "trace": {"sender": request.sender, "recipient": request.recipient, **trace}}
    except (ValueError, FileNotFoundError, FileExistsError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.get("/api/inbox/{identity}")
def inbox(identity: str) -> list[dict]:
    try:
        identity = validate_identity(identity)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    if identity not in _users():
        raise HTTPException(status_code=404, detail="Usuario no encontrado.")
    result = []
    if MESSAGES_DIR.exists():
        for path in MESSAGES_DIR.glob("*.json"):
            try:
                envelope = json.loads(path.read_text(encoding="utf-8"))
                if envelope.get("recipient") == identity:
                    result.append({
                        "id": path.stem,
                        "sender": envelope.get("sender", "desconocido"),
                        "sent_at_utc": envelope.get("sent_at_utc"),
                    })
            except (OSError, json.JSONDecodeError):
                continue
    return sorted(result, key=lambda item: item["sent_at_utc"] or "", reverse=True)


@app.post("/api/messages/{message_id}/receive")
def receive(message_id: str, request: ReceiveRequest) -> dict:
    path = _message_path(message_id)
    try:
        return receive_message(PKI_DIR, request.recipient, path, request.expected_sender)
    except (ValueError, FileNotFoundError, FileExistsError, InvalidSignature, InvalidTag) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.get("/api/messages/{message_id}/envelope")
def envelope(message_id: str) -> dict:
    path = _message_path(message_id)
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise HTTPException(status_code=400, detail="No se pudo leer el sobre.") from exc


@app.post("/api/messages/{message_id}/intercept")
def intercept(message_id: str, request: InterceptRequest) -> dict:
    path = _message_path(message_id)
    try:
        identity = validate_identity(request.identity)
        if identity not in _users():
            raise ValueError("Registra esa identidad como usuario antes de simular la interceptación.")
        return simulate_unauthorized_unwrap(PKI_DIR, identity, path)
    except (ValueError, FileNotFoundError, FileExistsError, json.JSONDecodeError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/api/labs/hash")
def hash_lab(request: LabTextRequest) -> dict:
    return avalanche_demo(request.message)


@app.post("/api/labs/aes-gcm")
def aes_lab(request: LabTextRequest) -> dict:
    plaintext = request.message.encode("utf-8")
    key = AESGCM.generate_key(bit_length=256)
    nonce = os.urandom(12)
    authenticated_ciphertext = AESGCM(key).encrypt(nonce, plaintext, None)
    ciphertext, tag = authenticated_ciphertext[:-16], authenticated_ciphertext[-16:]
    recovered = AESGCM(key).decrypt(nonce, ciphertext + tag, None).decode("utf-8")
    return {
        "algorithm": "AES-256-GCM",
        "key_b64_demo_only": b64e(key),
        "nonce_b64": b64e(nonce),
        "ciphertext_b64": b64e(ciphertext),
        "authentication_tag_b64": b64e(tag),
        "decrypted_message": recovered,
        "round_trip_ok": recovered == request.message,
        "note": "Esta clave se expone solo en este laboratorio efímero para mostrar el proceso. El flujo real nunca la expone.",
    }


@app.post("/api/labs/hybrid")
def hybrid_lab(request: LabTextRequest) -> dict:
    plaintext = request.message.encode("utf-8")
    receiver_key = generate_rsa_private_key()
    session_key = AESGCM.generate_key(bit_length=256)
    nonce = os.urandom(12)
    sealed = AESGCM(session_key).encrypt(nonce, plaintext, None)
    wrapped_key = rsa_oaep_encrypt(receiver_key.public_key(), session_key)
    unwrapped_key = rsa_oaep_decrypt(receiver_key, wrapped_key)
    recovered = AESGCM(unwrapped_key).decrypt(nonce, sealed, None).decode("utf-8")
    return {
        "content_cipher": "AES-256-GCM",
        "key_transport": "RSA-3072-OAEP-SHA256",
        "recipient_public_key_pem": receiver_key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode("ascii"),
        "wrapped_session_key_b64": b64e(wrapped_key),
        "nonce_b64": b64e(nonce),
        "ciphertext_and_tag_b64": b64e(sealed),
        "decrypted_message": recovered,
        "round_trip_ok": recovered == request.message,
        "note": "Se cifra el texto con AES y solo la clave AES con RSA. La clave privada RSA temporal no se muestra.",
    }


@app.post("/api/labs/signature")
def signature_lab(request: LabTextRequest) -> dict:
    plaintext = request.message.encode("utf-8")
    private_key = generate_rsa_private_key()
    public_key = private_key.public_key()
    signature = sign(private_key, plaintext)
    public_key.verify(signature, plaintext, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
    altered = bytearray(plaintext)
    altered[0] ^= 1
    try:
        public_key.verify(signature, bytes(altered), padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
        altered_verified = True
    except InvalidSignature:
        altered_verified = False
    return {
        "algorithm": "RSA-3072-PSS-SHA256",
        "public_key_pem": public_key.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode("ascii"),
        "message_sha256": hashlib.sha256(plaintext).hexdigest(),
        "signature_b64": b64e(signature),
        "original_signature_valid": True,
        "signature_valid_after_one_bit_change": altered_verified,
        "note": "La clave privada efímera firma; la clave pública verifica. Una modificación de un bit invalida la firma.",
    }


@app.get("/api/certificates/{identity}/validate")
def validate_user_certificate(identity: str) -> dict:
    try:
        identity = validate_identity(identity)
        ca_cert = load_certificate(PKI_DIR / "ca" / "ca_cert.pem")
        cert = load_certificate(PKI_DIR / "users" / identity / "certificate.pem")
        validate_certificate(cert, ca_cert, identity)
        public_key = cert.public_key()
        return {
            "identity": identity,
            "trusted": True,
            "issuer": cert.issuer.rfc4514_string(),
            "subject": cert.subject.rfc4514_string(),
            "valid_from_utc": cert.not_valid_before_utc.isoformat(),
            "valid_until_utc": cert.not_valid_after_utc.isoformat(),
            "public_key_type": type(public_key).__name__,
            "public_key_bits": public_key.key_size if isinstance(public_key, rsa.RSAPublicKey) else None,
            "checks": ["firma de la CA", "vigencia", "identidad"],
        }
    except (ValueError, FileNotFoundError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/api/labs/certificates/invalid")
def invalid_certificate_lab(request: InvalidCertificateRequest) -> dict:
    try:
        ca_cert = load_certificate(PKI_DIR / "ca" / "ca_cert.pem")
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "usuario-demo")])
        user_key = generate_rsa_private_key()
        now = datetime.now(timezone.utc)
        builder = (
            x509.CertificateBuilder().subject_name(subject).issuer_name(ca_cert.subject)
            .public_key(user_key.public_key()).serial_number(x509.random_serial_number())
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        )
        if request.scenario == "untrusted":
            # El issuer parece ser la CA, pero la firma se hace con una clave ajena.
            forged = builder.not_valid_before(now - timedelta(days=1)).not_valid_after(now + timedelta(days=1)).sign(user_key, hashes.SHA256())
            expected_error = "firma"
        else:
            ca_key = _read_private_key(PKI_DIR / "ca" / "ca_key.pem")
            forged = builder.not_valid_before(now - timedelta(days=3)).not_valid_after(now - timedelta(days=1)).sign(ca_key, hashes.SHA256())
            expected_error = "vigencia"
        try:
            validate_certificate(forged, ca_cert, "usuario-demo")
        except ValueError as exc:
            return {"trusted": False, "scenario": request.scenario, "rejected": True, "reason": str(exc)}
        return {"trusted": True, "scenario": request.scenario, "rejected": False, "reason": f"El certificado pasó inesperadamente la validación ({expected_error})."}
    except (ValueError, FileNotFoundError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
