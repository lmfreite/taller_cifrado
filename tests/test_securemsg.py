import json
from pathlib import Path
import tempfile
import unittest

from cryptography import x509
from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

from securemsg.certificates import init_ca, issue_user, load_certificate, validate_certificate
from securemsg.hashing import avalanche_demo
from securemsg.messaging import receive_message, send_message


class SecureMessagingTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name) / "pki"
        init_ca(self.root)
        issue_user(self.root, "ana")
        issue_user(self.root, "luis")
        self.envelope = Path(self.temp.name) / "message.json"
        send_message(self.root, "ana", "luis", "Mensaje íntegro", self.envelope)

    def tearDown(self):
        self.temp.cleanup()

    def test_integral_message_is_accepted(self):
        result = receive_message(self.root, "luis", self.envelope, "ana")
        self.assertTrue(result["accepted"])
        self.assertEqual(result["message"], "Mensaje íntegro")

    def test_altered_ciphertext_is_rejected(self):
        data = json.loads(self.envelope.read_text())
        data["ciphertext"] = ("A" if data["ciphertext"][0] != "A" else "B") + data["ciphertext"][1:]
        self.envelope.write_text(json.dumps(data))
        with self.assertRaises((InvalidTag, ValueError)):
            receive_message(self.root, "luis", self.envelope)

    def test_invalid_signature_is_rejected(self):
        data = json.loads(self.envelope.read_text())
        sender_key = serialization.load_pem_private_key((self.root / "users/ana/private_key.pem").read_bytes(), None)
        recipient_key = serialization.load_pem_private_key((self.root / "users/luis/private_key.pem").read_bytes(), None)
        from securemsg.crypto_utils import b64d, b64e, canonical_json, rsa_oaep_decrypt, rsa_oaep_encrypt
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        key = rsa_oaep_decrypt(recipient_key, b64d(data["wrapped_session_key"]))
        aad = canonical_json({"version": 1, "sender": "ana", "recipient": "luis"})
        sealed = b64d(data["ciphertext"]) + b64d(data["authentication_tag"])
        payload = json.loads(AESGCM(key).decrypt(b64d(data["nonce"]), sealed, aad))
        payload["signature"] = b64e(b"invalid signature")
        sealed = AESGCM(key).encrypt(b64d(data["nonce"]), canonical_json(payload), aad)
        data["ciphertext"], data["authentication_tag"] = b64e(sealed[:-16]), b64e(sealed[-16:])
        self.envelope.write_text(json.dumps(data))
        with self.assertRaises(InvalidSignature):
            receive_message(self.root, "luis", self.envelope)

    def test_certificate_not_signed_by_trusted_ca_is_rejected(self):
        ca = load_certificate(self.root / "ca/ca_cert.pem")
        cert = load_certificate(self.root / "users/ana/certificate.pem")
        # Un certificado con la misma identidad y clave, pero emisor ajeno, no encadena a la CA.
        rogue = x509.CertificateBuilder().subject_name(cert.subject).issuer_name(ca.subject)
        rogue = (rogue.public_key(cert.public_key()).serial_number(x509.random_serial_number())
                 .not_valid_before(cert.not_valid_before_utc).not_valid_after(cert.not_valid_after_utc)
                 .sign(serialization.load_pem_private_key((self.root / "users/luis/private_key.pem").read_bytes(), None), hashes.SHA256()))
        with self.assertRaises(ValueError):
            validate_certificate(rogue, ca, "ana")

    def test_expired_certificate_is_rejected(self):
        ca = load_certificate(self.root / "ca/ca_cert.pem")
        cert = load_certificate(self.root / "users/ana/certificate.pem")
        from datetime import datetime, timedelta, timezone
        key = serialization.load_pem_private_key((self.root / "ca/ca_key.pem").read_bytes(), None)
        expired = (x509.CertificateBuilder().subject_name(cert.subject).issuer_name(ca.subject)
                   .public_key(cert.public_key()).serial_number(x509.random_serial_number())
                   .not_valid_before(datetime.now(timezone.utc) - timedelta(days=3))
                   .not_valid_after(datetime.now(timezone.utc) - timedelta(days=1))
                   .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
                   .sign(key, hashes.SHA256()))
        with self.assertRaisesRegex(ValueError, "vigencia"):
            validate_certificate(expired, ca, "ana")

    def test_hash_demo_changes_one_input_bit_and_reports_digest_distance(self):
        result = avalanche_demo("A")
        self.assertEqual(result["changed_input_bit"], 1)
        self.assertEqual(result["output_bits"], 256)
        self.assertNotEqual(result["sha256"], result["modified_sha256"])


if __name__ == "__main__":
    unittest.main()
