#!/usr/bin/env python3
"""Encrypt a user-authorized one-time code for public transport to scoped CI."""
import argparse
import base64
import json
import os
import re
import sys
from pathlib import Path
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from create_apple_auth_form import validate_challenge, _unique_object


def encrypt_code(challenge, code, now=None):
    public = validate_challenge(challenge, now=now)
    if public['phase'] == 0 or not isinstance(code, str) or not re.fullmatch(r'[0-9]{6}', code):
        raise ValueError('A current confirmation-code challenge and six digits are required')
    key, iv = os.urandom(32), os.urandom(12)
    rsa = serialization.load_pem_public_key(public['public_key_spki_pem'].encode('ascii'))
    payload = json.dumps({'code': code}, separators=(',', ':')).encode('ascii')
    ciphertext = AESGCM(key).encrypt(iv, payload, base64.b64decode(public['context_b64'], validate=True))
    wrapped = rsa.encrypt(key, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
    envelope = {field: public[field] for field in ('version', 'run_id', 'phase', 'nonce', 'expires_at')}
    envelope.update(wrapped_key=base64.b64encode(wrapped).decode('ascii'),
                    iv=base64.b64encode(iv).decode('ascii'),
                    ciphertext=base64.b64encode(ciphertext).decode('ascii'))
    return envelope


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('public_challenge', type=Path)
    args = parser.parse_args()
    if args.public_challenge.stat().st_size > 16384:
        raise ValueError('Public challenge is too large')
    challenge = json.loads(args.public_challenge.read_text(), object_pairs_hook=_unique_object)
    code = sys.stdin.read(9).rstrip('\r\n')
    try:
        envelope = encrypt_code(challenge, code)
    finally:
        code = ''
    sys.stdout.write(json.dumps(envelope, separators=(',', ':')) + '\n')


if __name__ == '__main__':
    try:
        main()
    except Exception:
        sys.stderr.write('One-time code encryption failed; no code was saved.\n')
        sys.exit(1)
