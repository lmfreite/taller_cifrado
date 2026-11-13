"""Flujo híbrido de envío y recepción de mensajes."""

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .certificates import _read_private_key, load_certificate, validate_certificate, validate_identity
from .crypto_utils import AES_KEY_BYTES, GCM_NONCE_BYTES, b64d, b64e, canonical_json, rsa_oaep_decrypt, rsa_oaep_encrypt, sha256, sign


def send_message(root: Path, sender: str, recipient: str, message: str, output: Path) -> dict[str, str]:
    sender, recipient = validate_identity(sender), validate_identity(recipient)
    ca_cert = load_certificate(root / "ca" / "ca_cert.pem")
    sender_cert = load_certificate(root / "users" / sender / "certificate.pem")
    recipient_cert = load_certificate(root / "users" / recipient / "certificate.pem")
    validate_certificate(sender_cert, ca_cert, sender)
    validate_certificate(recipient_cert, ca_cert, recipient)
    sender_key = _read_private_key(root / "users" / sender / "private_key.pem")
    if sender_key.public_key().public_numbers() != sender_cert.public_key().public_numbers():
        raise ValueError("La clave privada del emisor no corresponde a su certificado.")

    plaintext = message.encode("utf-8")
    signature = sign(sender_key, plaintext)
    payload = canonical_json({"message": message, "sha256": sha256(plaintext).hex(), "signature": b64e(signature)})
    session_key = AESGCM.generate_key(bit_length=256)
    nonce = os.urandom(GCM_NONCE_BYTES)
    aad = canonical_json({"version": 1, "sender": sender, "recipient": recipient})
    ciphertext_and_tag = AESGCM(session_key).encrypt(nonce, payload, aad)
    ciphertext, authentication_tag = ciphertext_and_tag[:-16], ciphertext_and_tag[-16:]
    recipient_public_key = recipient_cert.public_key()
    if not isinstance(recipient_public_key, rsa.RSAPublicKey):
        raise ValueError("El certificado del destinatario no contiene una clave RSA.")
    envelope = {
        "version": 1,
        "algorithm": {"content": "AES-256-GCM", "key_wrap": "RSA-OAEP-SHA256", "signature": "RSA-PSS-SHA256"},
        "sender": sender,
        "recipient": recipient,
        "sent_at_utc": datetime.now(timezone.utc).isoformat(),
        "sender_certificate_pem": sender_cert.public_bytes(serialization.Encoding.PEM).decode("ascii"),
        "wrapped_session_key": b64e(rsa_oaep_encrypt(recipient_public_key, session_key)),
        "nonce": b64e(nonce),
        "ciphertext": b64e(ciphertext),
        "authentication_tag": b64e(authentication_tag),
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(envelope, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    # Son valores públicos del sobre o evidencia verificable; nunca devolver la clave AES.
    return {
        "plaintext_sha256": sha256(plaintext).hex(),
        "signature_b64": b64e(signature),
        "nonce_b64": b64e(nonce),
        "wrapped_session_key_b64": envelope["wrapped_session_key"],
        "ciphertext_b64": envelope["ciphertext"],
        "authentication_tag_b64": envelope["authentication_tag"],
        "aad": aad.decode("utf-8"),
    }


def simulate_unauthorized_unwrap(root: Path, identity: str, input_path: Path) -> dict[str, str | bool]:
    """Simula a otro usuario que obtiene el sobre e intenta desenvolver la clave AES."""
    identity = validate_identity(identity)
    envelope = json.loads(input_path.read_text(encoding="utf-8"))
    recipient = validate_identity(envelope["recipient"])
    if identity == recipient:
        raise ValueError("Elige una identidad distinta al destinatario para simular al interceptor.")
    private_key = _read_private_key(root / "users" / identity / "private_key.pem")
    try:
        session_key = rsa_oaep_decrypt(private_key, b64d(envelope["wrapped_session_key"]))
    except ValueError:
        return {
            "success": False,
            "identity": identity,
            "recipient": recipient,
            "result": "RSA-OAEP rechazó la clave envuelta: esta identidad no tiene la clave privada correspondiente al destinatario.",
        }
    if len(session_key) != AES_KEY_BYTES:
        return {"success": False, "identity": identity, "recipient": recipient, "result": "La clave desenvuelta no es una clave AES válida."}
    return {
        "success": True,
        "identity": identity,
        "recipient": recipient,
        "result": "La clave pudo desenvolverse. Esta identidad tiene la clave privada correspondiente al destinatario.",
    }


def receive_message(root: Path, recipient: str, input_path: Path, expected_sender: str | None = None) -> dict[str, Any]:
    recipient = validate_identity(recipient)
    try:
        envelope = json.loads(input_path.read_text(encoding="utf-8"))
        if envelope["version"] != 1 or envelope["recipient"] != recipient:
            raise ValueError("El sobre tiene una versión no compatible o está dirigido a otro destinatario.")
        sender = validate_identity(envelope["sender"])
        if expected_sender is not None and sender != validate_identity(expected_sender):
            raise ValueError(f"Emisor inesperado: {sender}.")
        ca_cert = load_certificate(root / "ca" / "ca_cert.pem")
        sender_cert = x509.load_pem_x509_certificate(envelope["sender_certificate_pem"].encode("ascii"))
        validate_certificate(sender_cert, ca_cert, sender)
        recipient_cert = load_certificate(root / "users" / recipient / "certificate.pem")
        validate_certificate(recipient_cert, ca_cert, recipient)
        recipient_key = _read_private_key(root / "users" / recipient / "private_key.pem")
        if recipient_key.public_key().public_numbers() != recipient_cert.public_key().public_numbers():
            raise ValueError("La clave privada del destinatario no corresponde a su certificado.")
        session_key = rsa_oaep_decrypt(recipient_key, b64d(envelope["wrapped_session_key"]))
        if len(session_key) != AES_KEY_BYTES:
            raise ValueError("Clave de sesión con longitud inesperada.")
        aad = canonical_json({"version": 1, "sender": sender, "recipient": recipient})
        sealed = b64d(envelope["ciphertext"])
        # Acepta los sobres previos a la separación de la etiqueta GCM para conservar mensajes existentes.
        if "authentication_tag" in envelope:
            sealed += b64d(envelope["authentication_tag"])
        payload_bytes = AESGCM(session_key).decrypt(b64d(envelope["nonce"]), sealed, aad)
        payload = json.loads(payload_bytes.decode("utf-8"))
        message = payload["message"]
        message_bytes = message.encode("utf-8")
        integrity_ok = sha256(message_bytes).hex() == payload["sha256"]
        if not integrity_ok:
            raise ValueError("Integridad rechazada: el hash SHA-256 no coincide.")
        sender_public_key = sender_cert.public_key()
        if not isinstance(sender_public_key, rsa.RSAPublicKey):
            raise ValueError("La clave del certificado del emisor no es RSA.")
        sender_public_key.verify(
            b64d(payload["signature"]), message_bytes,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256(),
        )
        return {
            "accepted": True,
            "sender": sender,
            "recipient": recipient,
            "message": message,
            "confidentiality": "OK (AES-256-GCM; clave protegida con RSA-OAEP)",
            "integrity": "OK (etiqueta GCM, SHA-256 y firma válidos)",
            "authenticity": "OK (certificado de la CA y firma RSA-PSS válidos)",
            "non_repudiation": "La firma identifica la clave del emisor; no constituye no repudio legal por sí sola.",
        }
    except (KeyError, TypeError, json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ValueError("Sobre inválido o incompleto.") from exc
