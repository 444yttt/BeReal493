#!/usr/bin/env python3
"""Create a public-safe v2 envelope using only the CI distribution public key.

The temporary HTTPS input URL is read from a local mode-600 file. It is never
printed, put in command arguments, or included as plaintext in the envelope.
"""
import argparse
import base64
import hashlib
import hmac
import importlib.util
import json
from pathlib import Path
import secrets
import stat
import sys


spec = importlib.util.spec_from_file_location('bereal_resign_contract', Path(__file__).with_name('bereal-resign.py'))
contract = importlib.util.module_from_spec(spec)
spec.loader.exec_module(contract)


def make_envelope(url, public_key, allowed_hosts):
    contract.validate_url_input(url, allowed_hosts)
    keys, iv = secrets.token_bytes(64), secrets.token_bytes(16)
    payload = json.dumps({'url': url, 'allowed_hosts': allowed_hosts}, separators=(',', ':')).encode()
    ciphertext = contract.run(['openssl', 'enc', '-aes-256-cbc', '-K', keys[:32].hex(), '-iv', iv.hex()], payload)
    wrapped = contract.run(['openssl', 'pkeyutl', '-encrypt', '-pubin', '-inkey', str(public_key),
                            '-pkeyopt', 'rsa_padding_mode:oaep', '-pkeyopt', 'rsa_oaep_md:sha256',
                            '-pkeyopt', 'rsa_mgf1_md:sha256'], keys)
    encode = lambda value: base64.b64encode(value).decode('ascii')
    return {'version': 2, 'mode': 'encrypted-https-url',
            'input_sha256': contract.ORIGINAL_SHA, 'source_commit': contract.SOURCE_COMMIT,
            'wrapped_keys': encode(wrapped), 'iv': encode(iv), 'encrypted_url': encode(ciphertext),
            'hmac': encode(hmac.new(keys[32:], contract.URL_INPUT_HMAC_DOMAIN + iv + ciphertext, hashlib.sha256).digest())}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--url-file', type=Path, required=True)
    parser.add_argument('--public-key', type=Path, required=True)
    parser.add_argument('--allowed-host', action='append', required=True)
    parser.add_argument('--output', type=Path, required=True)
    options = parser.parse_args(argv)
    contract.configure_openssl()
    metadata = options.url_file.stat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_mode & 0o077 or metadata.st_size > 32768:
        raise RuntimeError('The input URL must be stored in a local mode-600 file')
    envelope = make_envelope(options.url_file.read_text().strip(), options.public_key, options.allowed_host)
    options.output.write_text(json.dumps(envelope, indent=2) + '\n')
    print('Created encrypted URL input envelope; original SHA256 and adapter source commit are pinned.')


if __name__ == '__main__':
    try: main()
    except Exception as error:
        print('URL input preparation failed: ' + (str(error) if isinstance(error, RuntimeError) else type(error).__name__), file=sys.stderr)
        sys.exit(1)
