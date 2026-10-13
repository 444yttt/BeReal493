"""Offline guards for signing inputs and public-only readiness delivery."""
import base64
import copy
import datetime as dt
import importlib.util
import io
import json
import os
from pathlib import Path
import plistlib
import subprocess
import tempfile
import types
import unittest
from contextlib import redirect_stdout
from unittest.mock import Mock, patch


spec = importlib.util.spec_from_file_location('bereal_resign', Path(__file__).parents[1] / 'scripts/bereal-resign.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
TEAM = 'ABCDEFGHIJ'
DEVICE = 'LOCAL-TEST-DEVICE'
CERTIFICATE = b'test-only-certificate'
IDENTIFIER = module.ROOT_ID
UUID = 'ec6fb286-ece5-41ba-9080-2e5dafcb7ea3'


def future(value):
    if isinstance(value, str): value = dt.datetime.fromisoformat(value.replace('Z', '+00:00'))
    if not isinstance(value, dt.datetime): return False
    return value.replace(tzinfo=dt.timezone.utc) > dt.datetime.now(dt.timezone.utc)


def profile(identifier=IDENTIFIER):
    return {'UUID': UUID, 'TeamIdentifier': [TEAM], 'ApplicationIdentifierPrefix': [TEAM],
            'DeveloperCertificates': [CERTIFICATE], 'ExpirationDate': dt.datetime(2030, 10, 13),
            'ProvisionedDevices': [DEVICE], 'Entitlements': {
                'application-identifier': TEAM + '.' + identifier,
                'com.apple.developer.team-identifier': TEAM, 'get-task-allow': False,
                'keychain-access-groups': [TEAM + '.*']}}


def resource(decoded=None):
    return {'id': 'test-profile', 'attributes': {'profileType': 'IOS_APP_ADHOC',
            'profileState': 'ACTIVE', 'uuid': UUID, 'expirationDate': '2030-10-13T00:00:00Z',
            'profileContent': base64.b64encode(plistlib.dumps(decoded or profile())).decode()}}


class SigningInputTest(unittest.TestCase):
    def setUp(self):
        self.helper = patch.object(module, 'helper', types.SimpleNamespace(
            decode_base64=lambda value: base64.b64decode(value, validate=True), is_future=future))
        self.helper.start()
        self.addCleanup(self.helper.stop)

    def validate(self, decoded=None, remote=None):
        with patch.object(module, 'run', return_value=plistlib.dumps(decoded or profile())):
            return module.validate_profile(remote or resource(), CERTIFICATE, TEAM, IDENTIFIER, DEVICE)

    def test_keychain_grant_is_concrete_and_does_not_mutate_profile(self):
        original = profile()
        signed = module.concrete_entitlements(original, IDENTIFIER)
        self.assertEqual(signed['keychain-access-groups'], [TEAM + '.' + IDENTIFIER])
        self.assertEqual(original['Entitlements']['keychain-access-groups'], [TEAM + '.*'])
        self.validate()

    def test_rejects_wrong_team_certificate_or_device_permissions(self):
        changes = [
            ('TeamIdentifier', ['OTHERTEAM1']), ('DeveloperCertificates', [b'other-cert']),
            ('ProvisionedDevices', [DEVICE, 'OTHER-DEVICE']), ('ProvisionsAllDevices', True),
            ('ExpirationDate', dt.datetime(2020, 1, 1)), ('UUID', 'invalid')]
        for key, value in changes:
            with self.subTest(key=key), self.assertRaises(RuntimeError):
                decoded = profile(); decoded[key] = value
                self.validate(decoded)

    def test_rejects_original_identity_debug_or_unscoped_keychain(self):
        changes = [('application-identifier', TEAM + '.' + module.PREFIX),
                   ('com.apple.developer.team-identifier', 'OTHERTEAM1'),
                   ('get-task-allow', True), ('keychain-access-groups', ['OTHERTEAM1.*'])]
        for key, value in changes:
            with self.subTest(key=key), self.assertRaises(RuntimeError):
                decoded = profile(); decoded['Entitlements'][key] = value
                self.validate(decoded)

    def test_rejects_metadata_mismatch_or_expired_remote_profile(self):
        changes = [('uuid', 'different'), ('profileState', 'INVALID'),
                   ('profileType', 'IOS_APP_STORE'), ('expirationDate', '2020-01-01T00:00:00Z')]
        for key, value in changes:
            with self.subTest(key=key), self.assertRaises(RuntimeError):
                remote = resource(); remote['attributes'][key] = value
                self.validate(remote=remote)

    def test_read_failure_does_not_create_duplicate_profile(self):
        candidate = resource(); candidate['attributes'].pop('profileContent')
        api = Mock()
        api.collection.side_effect = [
            [{'id': 'bundle', 'attributes': {'identifier': IDENTIFIER, 'platform': 'IOS'}}],
            [candidate]]
        api.request.side_effect = RuntimeError('safe API error')
        with self.assertRaisesRegex(RuntimeError, 'safe API error'):
            module.get_profile(api, {'id': 'certificate'}, CERTIFICATE, TEAM, IDENTIFIER,
                               {'id': 'device', 'attributes': {'udid': DEVICE}})
        api.request.assert_called_once_with('GET', '/v1/profiles/test-profile')

    def test_unapproved_bundle_scope_fails_before_api_mutation(self):
        api = Mock()
        with self.assertRaises(RuntimeError):
            module.get_profile(api, {}, CERTIFICATE, TEAM, 'com.ayato.y3posclient', {})
        api.collection.assert_not_called(); api.request.assert_not_called()

    def test_public_receipt_contains_no_registered_device_identifier(self):
        receipt = module.public_profile_receipt(IDENTIFIER, profile(), CERTIFICATE)
        self.assertNotIn(DEVICE, json.dumps(receipt))
        self.assertEqual(receipt['provisioned_device_count'], 1)
        self.assertEqual(receipt['expiration_date'], '2030-10-13T00:00:00Z')
        self.assertEqual(len(receipt['certificate_sha256']), 64)

    def test_prepare_mode_needs_no_input_envelope_or_private_signing_key(self):
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, {
            'GITHUB_REPOSITORY': '444yttt/Y3POSClient', 'GITHUB_REF': 'refs/heads/main',
            'RUNNER_TEMP': directory}), patch.object(module, 'configure_openssl'), \
            patch.object(module, 'load_helper'), patch.object(module, 'decode_identity') as identity, \
            patch.object(module, 'signing_readiness', return_value=({}, {})), \
            patch.object(module, 'prepare_profiles') as prepare, \
            patch.object(module, 'decrypt_input') as decrypt:
            identity.return_value = (Path('p12'), CERTIFICATE, None, Path('asc'))
            module.main(['--prepare-profiles'])
            self.assertFalse(identity.call_args.kwargs['need_private_key'])
            prepare.assert_called_once(); decrypt.assert_not_called()

    def test_read_only_probe_mode_never_provisions_or_extracts_signing_key(self):
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, {
            'GITHUB_REPOSITORY': '444yttt/Y3POSClient', 'GITHUB_REF': 'refs/heads/main',
            'RUNNER_TEMP': directory}), patch.object(module, 'configure_openssl'), \
            patch.object(module, 'load_helper'), patch.object(module, 'decode_identity') as identity, \
            patch.object(module, 'signing_readiness', return_value=({}, {})), \
            patch.object(module, 'probe_existing_profiles') as probe, \
            patch.object(module, 'prepare_profiles') as prepare, \
            patch.object(module, 'decrypt_input') as decrypt:
            identity.return_value = (Path('p12'), CERTIFICATE, None, Path('asc'))
            module.main(['--probe-existing-profiles'])
            self.assertFalse(identity.call_args.kwargs['need_private_key'])
            probe.assert_called_once(); prepare.assert_not_called(); decrypt.assert_not_called()

    def test_wildcard_identifier_grants_cover_only_the_authorized_prefix(self):
        self.assertTrue(module.apple_identifier_grant_matches('*', IDENTIFIER))
        self.assertTrue(module.apple_identifier_grant_matches('com.ayato.*', IDENTIFIER))
        self.assertFalse(module.apple_identifier_grant_matches('com.ayato.*', 'com.ayatox.bereal493'))
        self.assertFalse(module.apple_identifier_grant_matches(IDENTIFIER + '.*', IDENTIFIER))
        self.assertFalse(module.apple_identifier_grant_matches('com.ayato.bereal*', IDENTIFIER))
        self.assertFalse(module.apple_identifier_grant_matches('com.*.bereal493', IDENTIFIER))

    def test_probe_reports_wildcard_coverage_without_weakening_strict_validator(self):
        decoded = profile('*')
        with patch.object(module, 'run', return_value=plistlib.dumps(decoded)):
            compatible = module.probe_profile_compatibility(resource(decoded), CERTIFICATE, TEAM, DEVICE)
            with self.assertRaises(RuntimeError):
                module.validate_profile(resource(decoded), CERTIFICATE, TEAM, IDENTIFIER, DEVICE)
        self.assertEqual(compatible['application_identifier_kind'], 'wildcard')
        self.assertEqual(compatible['compatible_scoped_identifiers'], [IDENTIFIER + suffix for suffix in module.SAFE_SUFFIXES])
        self.assertNotIn(DEVICE, json.dumps(compatible))
        self.assertEqual(decoded['Entitlements']['application-identifier'], TEAM + '.*')

    def test_probe_rejects_wrong_device_and_does_not_accept_ungranted_keychain(self):
        decoded = profile('*')
        with patch.object(module, 'run', return_value=plistlib.dumps(decoded)), self.assertRaises(RuntimeError):
            module.probe_profile_compatibility(resource(decoded), CERTIFICATE, TEAM, 'DIFFERENT-DEVICE')
        decoded['Entitlements']['keychain-access-groups'] = [TEAM + '.com.another.app']
        with patch.object(module, 'run', return_value=plistlib.dumps(decoded)):
            compatible = module.probe_profile_compatibility(resource(decoded), CERTIFICATE, TEAM, DEVICE)
        self.assertEqual(compatible['compatible_scoped_identifiers'], [])

    def test_probe_catalog_uses_get_only_and_publishes_no_raw_profile_or_udid(self):
        decoded = profile('*')
        candidate = resource(decoded)
        summary = copy.deepcopy(candidate); summary['attributes'].pop('profileContent')
        unrelated = {'id': 'unrelated', 'attributes': {'profileType': 'IOS_APP_STORE', 'profileState': 'ACTIVE'}}
        api = Mock()
        api.collection.return_value = [summary, unrelated]
        api.request.return_value = {'data': candidate}
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, {'APPLE_TEAM_ID': TEAM}), \
            patch.object(module, 'Path', return_value=Path(directory) / 'bereal-public'), \
            patch.object(module, 'run', side_effect=[plistlib.dumps(decoded), b'public-test-key']), \
            redirect_stdout(io.StringIO()):
            module.probe_existing_profiles(CERTIFICATE, api, {'attributes': {'udid': DEVICE}})
            receipt = json.loads((Path(directory) / 'bereal-public/existing-profile-probe.json').read_text())
        api.request.assert_called_once_with('GET', '/v1/profiles/test-profile')
        self.assertTrue(receipt['all_five_scoped_identifiers_covered'])
        self.assertFalse(receipt['apple_resources_created_or_modified'])
        self.assertEqual(receipt['catalog_distribution_types'], {'IOS_APP_ADHOC': 1, 'IOS_APP_STORE': 1})
        serialized = json.dumps(receipt)
        self.assertNotIn(DEVICE, serialized)
        self.assertNotIn(candidate['attributes']['profileContent'], serialized)
        self.assertNotIn('profileContent', serialized)

    def test_tool_diagnostics_never_expose_arguments_or_stderr(self):
        result = subprocess.CompletedProcess([], 3, b'', b'test-secret-stderr')
        with patch.object(module.subprocess, 'run', return_value=result), self.assertRaises(RuntimeError) as error:
            module.run(['security', 'import', '-P', 'test-secret-password'])
        self.assertNotIn('test-secret', str(error.exception))
        self.assertIn('security import', str(error.exception))


class CryptoCompatibilityTest(unittest.TestCase):
    def test_legacy_p12_and_authenticated_cms_round_trip(self):
        version = subprocess.run(['openssl', 'version'], capture_output=True)
        if not version.stdout.startswith(b'OpenSSL 3.'):
            self.skipTest('This compatibility check requires OpenSSL 3')
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, {'P12_PASSWORD': 'ephemeral-test-password'}):
            root = Path(directory)
            private_key, cert = root / 'key.pem', root / 'recipient.pem'
            module.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
                        '-subj', '/CN=EphemeralSigningTest', '-keyout', str(private_key), '-out', str(cert)])
            p12 = root / 'legacy.p12'
            module.run(['openssl', 'pkcs12', '-export', '-legacy', '-inkey', str(private_key),
                        '-in', str(cert), '-out', str(p12), '-passout', 'env:P12_PASSWORD'])
            self.assertIn(b'BEGIN CERTIFICATE', module.read_pkcs12(p12, ['-clcerts', '-nokeys']))
            self.assertIn(b'PRIVATE KEY', module.read_pkcs12(p12, ['-nocerts', '-nodes']))
            content = root / 'input'; content.write_bytes(b'local-ephemeral-test-data')
            cms = root / 'delivery.cms'
            module.run(['openssl', 'cms', '-encrypt', '-aes-256-gcm', '-binary', '-in', str(content),
                        '-outform', 'DER', '-out', str(cms), str(cert)])
            actual = module.run(['openssl', 'cms', '-decrypt', '-binary', '-inform', 'DER',
                                 '-in', str(cms), '-recip', str(cert), '-inkey', str(private_key)])
            self.assertEqual(actual, content.read_bytes())
            damaged = bytearray(cms.read_bytes()); damaged[-1] ^= 1; cms.write_bytes(damaged)
            with self.assertRaises(RuntimeError):
                module.run(['openssl', 'cms', '-decrypt', '-binary', '-inform', 'DER',
                            '-in', str(cms), '-recip', str(cert), '-inkey', str(private_key)])
