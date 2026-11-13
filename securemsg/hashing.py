"""Demostración de SHA-256, huella y efecto avalancha de un bit."""

import hashlib


def avalanche_demo(message: str) -> dict[str, str | int]:
    original = message.encode("utf-8")
    changed = bytearray(original or b"\x00")
    changed[0] ^= 0x01
    digest_a = hashlib.sha256(original).hexdigest()
    digest_b = hashlib.sha256(changed).hexdigest()
    differing_bits = sum((a ^ b).bit_count() for a, b in zip(bytes.fromhex(digest_a), bytes.fromhex(digest_b)))
    return {
        "sha256": digest_a,
        "modified_sha256": digest_b,
        "changed_input_bit": 1,
        "different_output_bits": differing_bits,
        "output_bits": 256,
    }
