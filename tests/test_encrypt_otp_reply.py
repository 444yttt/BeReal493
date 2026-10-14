import base64
import json
import pathlib
import subprocess
import sys
import tempfile
import time
import unittest
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

SCRIPT_ROOT = pathlib.Path(__file__).resolve().parents[1] / 'scripts'
sys.path.insert(0, str(SCRIPT_ROOT))
from encrypt_otp_reply import encrypt_code


class OTPTransportTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.private = rsa.generate_private_key(public_exponent=65537, key_size=3072)

    def challenge(self, phase=1):
        expires = int(time.time()) + 600
        nonce = 'b' * 64
        context = f'BeReal493AppleAuthRelayV1|12345|{phase}|{nonce}|{expires}'.encode()
        return dict(version=1, purpose='bereal-apple-auth', run_id='12345', phase=phase,
                    nonce=nonce, expires_at=expires,
                    public_key_spki_pem=self.private.public_key().public_bytes(
                        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode(),
                    context_b64=base64.b64encode(context).decode(),
                    allowed_payload='credentials' if phase == 0 else 'two_factor')

    def decrypt(self, challenge, envelope):
        key = self.private.decrypt(base64.b64decode(envelope['wrapped_key']), padding.OAEP(
            mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
        return AESGCM(key).decrypt(base64.b64decode(envelope['iv']),
                                  base64.b64decode(envelope['ciphertext']),
                                  base64.b64decode(challenge['context_b64']))

    def test_exact_ci_wire_protocol_and_tampering(self):
        challenge = self.challenge()
        envelope = encrypt_code(challenge, '123456')
        self.assertEqual(set(envelope), {'version', 'run_id', 'phase', 'nonce', 'expires_at',
                                         'wrapped_key', 'iv', 'ciphertext'})
        self.assertEqual(json.loads(self.decrypt(challenge, envelope)), {'code': '123456'})
        tampered = dict(envelope)
        body = bytearray(base64.b64decode(envelope['ciphertext'])); body[0] ^= 1
        tampered['ciphertext'] = base64.b64encode(body).decode()
        with self.assertRaises(InvalidTag):
            self.decrypt(challenge, tampered)

    def test_login_phase_expiry_and_non_ascii_codes_rejected(self):
        with self.assertRaises(ValueError):
            encrypt_code(self.challenge(0), '123456')
        expired = self.challenge()
        with self.assertRaises(ValueError):
            encrypt_code(expired, '123456', now=expired['expires_at'])
        for code in ['12345', '1234567', '１２３４５６', ' 123456', 123456]:
            with self.assertRaises(ValueError):
                encrypt_code(self.challenge(), code)

    def test_cli_outputs_ciphertext_only_and_never_echoes_invalid_input(self):
        with tempfile.TemporaryDirectory() as directory:
            challenge = self.challenge()
            path = pathlib.Path(directory) / 'challenge.json'
            path.write_text(json.dumps(challenge))
            command = [sys.executable, str(SCRIPT_ROOT / 'encrypt_otp_reply.py'), str(path)]
            ok = subprocess.run(command, input='123456\n', text=True, capture_output=True)
            self.assertEqual(ok.returncode, 0)
            self.assertEqual(ok.stderr, '')
            self.assertEqual(json.loads(self.decrypt(challenge, json.loads(ok.stdout))), {'code': '123456'})
            bad = subprocess.run(command, input='private-invalid-input', text=True, capture_output=True)
            self.assertNotEqual(bad.returncode, 0)
            self.assertEqual(bad.stdout, '')
            self.assertNotIn('private-invalid-input', bad.stderr)


if __name__ == '__main__':
    unittest.main()
