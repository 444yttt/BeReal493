"""Local crypto and URL checks; no real input URLs or signing assets are used."""
import base64
import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch
from unittest.mock import MagicMock, Mock
import urllib.error
import urllib.request
import zipfile


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).parents[1] / 'scripts' / filename)
    result = importlib.util.module_from_spec(spec); spec.loader.exec_module(result)
    return result


module = load('url_signing_contract', 'bereal-resign.py')
generator = load('url_envelope_generator', 'prepare_url_envelope.py')
URL = 'https://cvws.icloud-content.com/ephemeral-test.ipa?token=local-test-credential'
HOSTS = ['*.icloud-content.com']


class URLScopeTest(unittest.TestCase):
    def test_rejects_http_other_domains_userinfo_and_non443_ports(self):
        invalid = ['http://cvws.icloud-content.com/test', 'https://icloud-content.com/test',
                   'https://evil.example/test', 'https://cvws.icloud-content.com.evil.example/test',
                   'https://user@cvws.icloud-content.com/test', 'https://cvws.icloud-content.com:444/test',
                   URL + '#fragment', URL + '\n']
        for url in invalid:
            with self.subTest(url=url), self.assertRaises(RuntimeError): module.validate_url_input(url, HOSTS)

    def test_cloud_shard_redirect_remains_scoped(self):
        handler = module.ScopedInputRedirects(HOSTS)
        request = urllib.request.Request(URL)
        new = handler.redirect_request(request, None, 302, '', {}, 'https://another-shard.icloud-content.com/test')
        self.assertEqual(new.full_url, 'https://another-shard.icloud-content.com/test')
        with self.assertRaises(RuntimeError):
            handler.redirect_request(request, None, 302, '', {}, 'https://evil.example/test')

    def test_prepare_input_mode_never_enters_profile_or_signing_flow(self):
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, {
            'GITHUB_REPOSITORY': '444yttt/Y3POSClient', 'GITHUB_REF': 'refs/heads/main',
            'RUNNER_TEMP': directory}), patch.object(module, 'configure_openssl'), \
            patch.object(module, 'load_helper'), patch.object(module, 'decode_identity', return_value=(None, b'cert', None, None)), \
            patch.object(module, 'signing_readiness', return_value=({}, {})), \
            patch.object(module, 'decrypt_input', return_value=Path('original.ipa')), \
            patch.object(module, 'prepare_input') as prepare, patch.object(module, 'get_profile') as profile, \
            patch.object(module.Path, 'read_text', return_value='{}'):
            module.main(['--prepare-input'])
            prepare.assert_called_once(); profile.assert_not_called()

    def test_verify_input_mode_emits_only_safe_receipt_and_never_rebuilds(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); original = root / 'original.ipa'; original.write_bytes(b'local-test-input')
            def local_path(value):
                path = Path(value)
                return root / path if str(path) in ('bereal-public', 'bereal-signing-input.json') else path
            (root / 'bereal-signing-input.json').write_text('{"version":3}')
            with patch.dict(os.environ, {'GITHUB_REPOSITORY': '444yttt/Y3POSClient',
                'GITHUB_REF': 'refs/heads/main', 'RUNNER_TEMP': directory}), \
                patch.object(module, 'configure_openssl'), patch.object(module, 'load_helper'), \
                patch.object(module, 'decode_identity', return_value=(None, b'cert', None, None)), \
                patch.object(module, 'signing_readiness', return_value=({}, {})), \
                patch.object(module, 'decrypt_input', return_value=original), \
                patch.object(module, 'build_adapter') as build, patch.object(module, 'get_profile') as profile, \
                patch.object(module, 'Path', side_effect=local_path), redirect_stdout(io.StringIO()):
                module.main(['--verify-input'])
            build.assert_not_called(); profile.assert_not_called()
            receipt = json.loads((root / 'bereal-public/input-verification.json').read_text())
            self.assertTrue(receipt['input_sha256_verified'])
            self.assertFalse(receipt['apple_resources_created_or_modified'])
            self.assertEqual(receipt['envelope_version'], 3)
            self.assertEqual(receipt['input_bytes'], len(b'local-test-input'))
            self.assertEqual([path.name for path in (root / 'bereal-public').iterdir()], ['input-verification.json'])

    def test_artifact_credentials_are_not_forwarded_to_signed_download_url(self):
        location = 'https://productionresults.blob.core.windows.net/artifact.zip?sig=ephemeral-test'
        api, unsigned = Mock(), Mock()
        api.open.side_effect = urllib.error.HTTPError('https://api.github.com', 302, 'Found', {'Location': location}, io.BytesIO())
        response = Mock(); response.geturl.return_value = location
        response.read.side_effect = [b'local-artifact-bytes', b'']
        context = MagicMock(); context.__enter__.return_value = response
        unsigned.open.return_value = context
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, {'GH_TOKEN': 'ephemeral-test-token'}), \
            patch.object(module.urllib.request, 'build_opener', side_effect=[api, unsigned]):
            archive = Path(directory) / 'artifact.zip'
            module.fetch_artifact_archive(1, archive)
            self.assertEqual(archive.read_bytes(), b'local-artifact-bytes')
        self.assertEqual(api.open.call_args.args[0].get_header('Authorization'), 'Bearer ephemeral-test-token')
        self.assertIsNone(unsigned.open.call_args.args[0].get_header('Authorization'))

    def test_artifact_redirect_domains_and_scheme_are_restricted(self):
        module.validate_artifact_url('https://productionresults.blob.core.windows.net/test')
        module.validate_artifact_url('https://results.actions.githubusercontent.com/test')
        for url in ('https://evil.example/test', 'http://productionresults.blob.core.windows.net/test',
                    'https://user@productionresults.blob.core.windows.net/test',
                    'https://productionresults.blob.core.windows.net:444/test'):
            with self.subTest(url=url), self.assertRaises(RuntimeError): module.validate_artifact_url(url)


class EnvelopeCryptoTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        module.configure_openssl()
        cls.temporary = tempfile.TemporaryDirectory()
        cls.root = Path(cls.temporary.name)
        cls.key, cls.cert, cls.public = cls.root / 'key.pem', cls.root / 'cert.pem', cls.root / 'public.pem'
        module.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
                    '-subj', '/CN=EphemeralURLTest', '-keyout', str(cls.key), '-out', str(cls.cert)])
        cls.der = module.run(['openssl', 'x509', '-in', str(cls.cert), '-outform', 'DER'])
        cls.public.write_bytes(module.run(['openssl', 'pkey', '-in', str(cls.key), '-pubout']))

    @classmethod
    def tearDownClass(cls): cls.temporary.cleanup()

    def test_url_envelope_round_trip_has_no_plaintext_url_and_verifies_original_hash(self):
        content = b'ephemeral original input test'
        envelope = generator.make_envelope(URL, self.public, HOSTS)
        self.assertNotIn('local-test-credential', json.dumps(envelope))
        self.assertNotIn('icloud-content.com', json.dumps(envelope))
        digest = hashlib.sha256(content).hexdigest(); envelope['input_sha256'] = digest
        with tempfile.TemporaryDirectory() as directory, patch.object(module, 'ORIGINAL_SHA', digest), \
            patch.object(module, 'download_url_input') as download, redirect_stdout(io.StringIO()):
            download.side_effect = lambda url, path, allowed: path.write_bytes(content)
            original = module.decrypt_input(Path(directory), self.key, envelope)
            self.assertEqual(original.read_bytes(), content)
            self.assertEqual(download.call_args.args[0], URL)
            self.assertEqual(download.call_args.args[2], HOSTS)

    def test_ciphertext_tamper_fails_before_any_download(self):
        envelope = generator.make_envelope(URL, self.public, HOSTS)
        ciphertext = bytearray(base64.b64decode(envelope['encrypted_url'])); ciphertext[0] ^= 1
        envelope['encrypted_url'] = base64.b64encode(ciphertext).decode()
        with tempfile.TemporaryDirectory() as directory, patch.object(module, 'download_url_input') as download, \
            self.assertRaisesRegex(RuntimeError, 'authentication failed'):
            module.decrypt_input(Path(directory), self.key, envelope)
        download.assert_not_called()

    def test_fresh_envelope_does_not_reuse_ciphertext_or_keys(self):
        first = generator.make_envelope(URL, self.public, HOSTS)
        second = generator.make_envelope(URL, self.public, HOSTS)
        for name in ('iv', 'wrapped_keys', 'encrypted_url', 'hmac'): self.assertNotEqual(first[name], second[name])

    def test_persistent_input_round_trip(self):
        content = b'persistent original test bytes'; digest = hashlib.sha256(content).hexdigest()
        with tempfile.TemporaryDirectory() as directory, patch.object(module, 'ORIGINAL_SHA', digest), redirect_stdout(io.StringIO()):
            root = Path(directory); original = root / 'source.ipa'; original.write_bytes(content)
            def local_path(value):
                path = Path(value)
                return root / path if str(path) == 'bereal-input-transfer' else path
            with patch.object(module, 'Path', side_effect=local_path):
                envelope = module.encrypt_persistent_input(root, original, self.der)
                restored = module.decrypt_input(root, self.key, envelope)
            self.assertEqual(restored.read_bytes(), content)
            self.assertEqual(envelope['version'], 3)
            self.assertNotIn(content.decode(), (root / 'bereal-input-transfer/input-metadata.json').read_text())
            encrypted = root / 'bereal-input-transfer/input-encrypted.bin'
            encrypted.write_bytes(encrypted.read_bytes()[:-1])
            with patch.object(module, 'Path', side_effect=local_path), self.assertRaises(RuntimeError):
                module.decrypt_input(root, self.key, envelope)

    def test_github_artifact_input_is_pinned_and_decrypts_the_original(self):
        content = b'github artifact original bytes'; digest = hashlib.sha256(content).hexdigest()
        with tempfile.TemporaryDirectory() as directory, patch.object(module, 'ORIGINAL_SHA', digest), redirect_stdout(io.StringIO()):
            root = Path(directory); original = root / 'source.ipa'; original.write_bytes(content)
            def local_path(value):
                path = Path(value)
                return root / path if str(path) == 'bereal-input-transfer' else path
            with patch.object(module, 'Path', side_effect=local_path):
                envelope = module.encrypt_persistent_input(root, original, self.der)
            archive = root / 'source-artifact.zip'
            with zipfile.ZipFile(archive, 'w') as target:
                for filename in ('input-encrypted.bin', 'input-metadata.json'):
                    target.write(root / 'bereal-input-transfer' / filename, filename)
            archive_content = archive.read_bytes()
            pinned = copy.deepcopy(envelope)
            pinned['github_artifact'] = {'repository': '444yttt/Y3POSClient', 'artifact_id': 1,
                                        'archive_sha256': hashlib.sha256(archive_content).hexdigest()}
            with patch.object(module, 'fetch_artifact_archive', side_effect=lambda identifier, path: path.write_bytes(archive_content)) as fetch:
                restored = module.decrypt_input(root, self.key, pinned)
                self.assertEqual(restored.read_bytes(), content)
                fetch.assert_called_once_with(1, root / 'encrypted-input-artifact.zip')
            pinned['github_artifact']['archive_sha256'] = '0' * 64
            with patch.object(module, 'fetch_artifact_archive', side_effect=lambda identifier, path: path.write_bytes(archive_content)), \
                self.assertRaisesRegex(RuntimeError, 'archive hash mismatch'):
                module.decrypt_input(root, self.key, pinned)
