"""Primitivas y serialización usadas por el sistema."""

import base64
import hashlib
import json
import os
from typing import Any

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

RSA_BITS = 3072
AES_KEY_BYTES = 32
GCM_NONCE_BYTES = 12


def canonical_json(data: dict[str, Any]) -> bytes:
    return json.dumps(data, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def b64d(data: str) -> bytes:
    try:
        return base64.b64decode(data, validate=True)
    except Exception as exc:
        raise ValueError("El mensaje contiene Base64 inválido.") from exc


def generate_rsa_private_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=RSA_BITS)


def rsa_oaep_encrypt(public_key: rsa.RSAPublicKey, data: bytes) -> bytes:
    return public_key.encrypt(
        data,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
    )


def rsa_oaep_decrypt(private_key: rsa.RSAPrivateKey, data: bytes) -> bytes:
    return private_key.decrypt(
        data,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
    )


def sign(private_key: rsa.RSAPrivateKey, data: bytes) -> bytes:
    return private_key.sign(
        data,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256(),
    )
