"""Synthetic delivery verification; no Apple assets or third-party IPA needed."""
import datetime as dt
import hashlib
import importlib.util
import json
from pathlib import Path
import plistlib
import struct
import subprocess
import tempfile
import unittest
import uuid
import zipfile
from unittest.mock import patch


spec = importlib.util.spec_from_file_location(
    'verify_signed_delivery', Path(__file__).parents[1] / 'scripts/verify_signed_delivery.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
TEAM = 'TEAM123456'
DEVICE = 'SYNTHETIC-DEVICE-DO-NOT-INCLUDE-IN-OUTPUT'


class SignedDeliveryTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not hasattr(hashlib, 'file_digest'):
            raise unittest.SkipTest('Delivery verification requires Python 3.11+')
        try:
            version = subprocess.run(['openssl', 'version'], capture_output=True)
        except FileNotFoundError:
            raise unittest.SkipTest('OpenSSL is unavailable')
        if not version.stdout.startswith(b'OpenSSL 3.'):
            raise unittest.SkipTest('Synthetic CMS verification requires OpenSSL 3')
        cls.temporary = tempfile.TemporaryDirectory(prefix='bereal-synthetic-signing-test-')
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.root = Path(cls.temporary.name)
        cls.key, cls.cert = cls.root / 'ephemeral-key.pem', cls.root / 'ephemeral-cert.pem'
        cls.openssl(['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '2',
                     '-subj', '/OU=' + TEAM + '/CN=Apple Distribution: Synthetic Fixture',
                     '-keyout', str(cls.key), '-out', str(cls.cert)])
        cls.der = cls.openssl(['x509', '-in', str(cls.cert), '-outform', 'DER'])
        # Keep the real checker and instruction replacements, but place a
        # synthetic factory in this fixture's single signed code page.
        cls.auth_original_context = bytearray(bytes.fromhex('1f2003d5') * 20)
        cls.auth_targets = tuple((512 + offset - module.AUTH_PATCH.FACTORY_CONTEXT_OFFSET,
                                  expected, replacement, register)
                                 for offset, expected, replacement, register in module.AUTH_PATCH.PATCHES)
        for offset, expected, _, _ in cls.auth_targets:
            cls.auth_original_context[offset - 512:offset - 508] = expected
        cls.auth_patched_context = bytearray(cls.auth_original_context)
        for offset, _, replacement, _ in cls.auth_targets:
            cls.auth_patched_context[offset - 512:offset - 508] = replacement
        scope = patch.multiple(module.AUTH_PATCH, FACTORY_CONTEXT_OFFSET=512, PATCHES=cls.auth_targets,
                               ORIGINAL_CONTEXT_SHA256=hashlib.sha256(cls.auth_original_context).hexdigest(),
                               PATCHED_CONTEXT_SHA256=hashlib.sha256(cls.auth_patched_context).hexdigest())
        scope.start(); cls.addClassCleanup(scope.stop)
        cls.payload, cls.profile_receipts = cls.make_payload()

    @classmethod
    def make_payload(cls, grant=None, signed_wildcards=False, profile_keychain=None, signed_token=False):
        payload, profile_receipts = {}, []
        now = dt.datetime.now(dt.timezone.utc).replace(tzinfo=None, microsecond=0)
        common_uuid = str(uuid.uuid4()) if grant is not None else None
        common_raw = None
        for suffix in module.SUFFIXES:
            identifier = module.ROOT_ID + suffix
            bundle = 'Payload/BeReal.app' + ('' if not suffix else '/PlugIns/' + suffix[1:] + '.appex')
            info = plistlib.dumps({'CFBundleIdentifier': identifier, 'CFBundleExecutable': 'Executable',
                                   'CFBundleShortVersionString': '4.93.0', 'CFBundleVersion': '23026'})
            resources = plistlib.dumps({'files': {}})
            entitlements = {'application-identifier': TEAM + '.' + (identifier if grant is None else grant),
                            'com.apple.developer.team-identifier': TEAM, 'get-task-allow': False,
                            'keychain-access-groups': [TEAM + '.*'] if profile_keychain is None else profile_keychain}
            profile = {'UUID': common_uuid or str(uuid.uuid4()), 'Entitlements': entitlements,
                       'TeamIdentifier': [TEAM], 'ApplicationIdentifierPrefix': [TEAM],
                       'ProvisionedDevices': [DEVICE], 'DeveloperCertificates': [cls.der],
                       'CreationDate': now - dt.timedelta(days=1),
                       'ExpirationDate': now + dt.timedelta(days=1)}
            # Construct fixture rights independently of the verifier, so an
            # incorrect profile-grant implementation cannot bless itself.
            concrete = dict(entitlements)
            concrete['application-identifier'] = TEAM + '.' + identifier
            concrete['keychain-access-groups'] = [TEAM + '.' + identifier]
            if signed_token:
                concrete['keychain-access-groups'].append('com.apple.token')
            payload[bundle + '/Info.plist'] = info
            payload[bundle + '/_CodeSignature/CodeResources'] = resources
            if grant is not None and common_raw is not None:
                raw = common_raw
            else:
                raw = cls.cms(plistlib.dumps(profile), attached=True)
                if grant is not None:
                    common_raw = raw
            payload[bundle + '/embedded.mobileprovision'] = raw
            payload[bundle + '/Executable'] = cls.executable(
                identifier, entitlements if signed_wildcards else concrete, info, resources, adapter=not suffix)
            profile_receipts.append({'bundle_identifier': identifier, 'profile_uuid': profile['UUID'],
                                     'expiration_date': profile['ExpirationDate'].isoformat() + 'Z',
                                     'entitlement_keys': sorted(concrete),
                                     'certificate_sha256': hashlib.sha256(cls.der).hexdigest(),
                                     'provisioned_device_count': 1})
        payload['Payload/BeReal.app/Frameworks/CameraRollAdapter.dylib'] = cls.executable('CameraRollAdapter')
        return payload, profile_receipts

    @classmethod
    def openssl(cls, arguments, data=None):
        result = subprocess.run(['openssl', *arguments], input=data, capture_output=True)
        if result.returncode:
            raise AssertionError('Synthetic OpenSSL command failed: ' + arguments[0])
        return result.stdout

    @classmethod
    def cms(cls, data, attached=False):
        arguments = ['cms', '-sign', '-binary', '-signer', str(cls.cert), '-inkey', str(cls.key),
                     '-outform', 'DER', '-nosmimecap', '-noattr', '-md', 'sha256']
        if attached:
            arguments.append('-nodetach')
        return cls.openssl(arguments, data)

    @staticmethod
    def blob(magic, data):
        return struct.pack('>II', magic, len(data) + 8) + data

    @classmethod
    def executable(cls, identifier, entitlements=None, info=None, resources=None, adapter=False, auth_context=None):
        """Create a minimal ARM64 image with CMS-bound page and metadata hashes.

        The DER blob deliberately has no entitlement semantics: the verifier
        claims presence/hash verification only and compares the XML dictionary.
        """
        xml = cls.blob(0xFADE7171, plistlib.dumps(entitlements)) if entitlements else None
        der = cls.blob(0xFADE7172, b'\x30\x00') if entitlements else None
        load = struct.pack('<4I', 0x1D, 16, 4096, 0)
        if adapter:
            dependency = module.ADAPTER.encode() + b'\0'
            size = (24 + len(dependency) + 7) & ~7
            load += (struct.pack('<6I', 0xC, size, 24, 0, 0x10000, 0x10000)
                     + dependency + b'\0' * (size - 24 - len(dependency)))
        executable = bytearray(struct.pack('<8I', 0xFEEDFACF, 0x0100000C, 0, 2,
                                           2 if adapter else 1, len(load), 0, 0) + load)
        executable += b'\0' * (4096 - len(executable))
        if adapter:
            context = cls.auth_patched_context if auth_context is None else auth_context
            executable[512:512 + len(context)] = context

        def signature():
            ident = identifier.encode() + b'\0'
            strings = ident + TEAM.encode() + b'\0'
            special_count = 7 if entitlements else 0
            values = {1: info, 3: resources, 5: xml, 7: der}
            hashes = b''.join(hashlib.sha256(values[slot]).digest() if values.get(slot) is not None
                              else b'\0' * 32 for slot in range(special_count, 0, -1))
            hash_offset = 52 + len(strings) + len(hashes)
            directory = (struct.pack('>9I4B3I', 0xFADE0C02, hash_offset + 32, 0x20200, 0,
                                     hash_offset, 52, special_count, 1, 4096, 32, 2, 0, 12,
                                     0, 0, 52 + len(ident))
                         + strings + hashes + hashlib.sha256(executable).digest())
            entries = [(0, directory)]
            if xml:
                entries.extend([(5, xml), (7, der)])
            entries.append((0x10000, cls.blob(0xFADE0B01, cls.cms(directory))))
            offset, index, content = 12 + 8 * len(entries), b'', b''
            for slot, value in entries:
                index += struct.pack('>II', slot, offset)
                content += value
                offset += len(value)
            return struct.pack('>III', 0xFADE0CC0, offset, len(entries)) + index + content

        first = signature()
        struct.pack_into('<I', executable, 44, len(first))
        final = signature()
        if len(first) != len(final):
            raise AssertionError('Fixture CMS size changed after filling LC_CODE_SIGNATURE')
        return bytes(executable) + final

    def setUp(self):
        self.delivery_directory = tempfile.TemporaryDirectory(dir=self.root, prefix='delivery-')
        self.addCleanup(self.delivery_directory.cleanup)
        delivery = Path(self.delivery_directory.name)
        self.ipa = delivery / 'BeReal493-CameraRoll-SIGNED.ipa'
        self.receipt = delivery / 'verification.json'

    def save_delivery(self, changed=None, extra=None, payload=None, profiles=None, wildcard=False):
        with zipfile.ZipFile(self.ipa, 'w') as archive:
            for name, value in (self.payload if payload is None else payload).items():
                archive.writestr(name, (changed or {}).get(name, value))
            if extra:
                archive.writestr(*extra)
        receipt = {'file': self.ipa.name, 'sha256': module.digest_file(self.ipa),
                   'source_commit': module.SOURCE_COMMIT, 'input_source_commit': module.INPUT_SOURCE_COMMIT,
                   'input_sha256': module.ORIGINAL_SHA,
                   'auth_keychain_patch': module.AUTH_PATCH.public_receipt(),
                   'bundle_identifier': module.ROOT_ID, 'distribution': 'IOS_APP_ADHOC',
                   'registered_device_count': 1, 'provisioned_bundle_count': 5,
                   'signature_verification': ('codesign deep strict passed; each app/extension matched '
                                              'concrete profile entitlements and the approved certificate'),
                   'device_installation': 'not tested', 'posting': 'not tested',
                   'certificate_sha256': hashlib.sha256(self.der).hexdigest(),
                   'profiles': self.profile_receipts if profiles is None else profiles}
        if wildcard:
            receipt['profile_selection'] = 'existing_wildcard_read_only'
            receipt['distinct_profile_count'] = 1
        self.receipt.write_text(json.dumps(receipt))

    def test_signed_delivery_validates_without_publishing_device_identifier(self):
        self.save_delivery()
        result = module.verify(self.ipa, self.receipt)
        verified = result['independently_verified']
        self.assertEqual(verified['signed_macho_file_count'], 6)
        self.assertEqual(verified['bundle_count'], 5)
        self.assertTrue(verified['same_single_provisioned_device'])
        self.assertTrue(verified['cms_signature_and_code_page_hashes'])
        self.assertTrue(all(profile['xml_entitlements_match_concrete_profile'] for profile in verified['profiles']))
        self.assertNotIn(DEVICE, json.dumps(result))
        self.assertIn('not independently checked', result['limitations'][0])

    def test_signed_code_tampering_is_rejected_even_with_updated_receipt_hash(self):
        path = 'Payload/BeReal.app/Executable'
        damaged = bytearray(self.payload[path])
        damaged[1000] ^= 1
        self.save_delivery(changed={path: bytes(damaged)})
        with self.assertRaisesRegex(ValueError, 'code-page hash mismatch'):
            module.verify(self.ipa, self.receipt)

    def test_missing_auth_patch_receipt_is_rejected(self):
        self.save_delivery()
        receipt = json.loads(self.receipt.read_text())
        receipt.pop('auth_keychain_patch')
        self.receipt.write_text(json.dumps(receipt))
        with self.assertRaisesRegex(ValueError, 'authentication storage patch'):
            module.verify(self.ipa, self.receipt)

    def resign_root_factory(self, context):
        root = 'Payload/BeReal.app/'
        old = self.payload[root + 'Executable']
        records = module.verify_macho(old, self.root, {}, dt.datetime.now(dt.timezone.utc))
        entitlements = records[0]['xml_entitlements']
        return self.executable(module.ROOT_ID, entitlements,
                               self.payload[root + 'Info.plist'], self.payload[root + '_CodeSignature/CodeResources'],
                               adapter=True, auth_context=context)

    def test_validly_resigned_partial_auth_patch_is_rejected(self):
        context = bytearray(self.auth_patched_context)
        offset, expected, _, _ = self.auth_targets[0]
        context[offset - 512:offset - 508] = expected
        self.save_delivery(changed={'Payload/BeReal.app/Executable': self.resign_root_factory(context)})
        with self.assertRaisesRegex(ValueError, 'argument writer'):
            module.verify(self.ipa, self.receipt)

    def test_validly_resigned_auth_factory_context_change_is_rejected(self):
        context = bytearray(self.auth_patched_context); context[0] ^= 1
        self.save_delivery(changed={'Payload/BeReal.app/Executable': self.resign_root_factory(context)})
        with self.assertRaisesRegex(ValueError, 'factory context'):
            module.verify(self.ipa, self.receipt)

    def test_unsafe_zip_path_is_rejected(self):
        self.save_delivery(extra=('Payload/BeReal.app/../outside', b'unsafe-fixture'))
        with self.assertRaisesRegex(ValueError, 'Unsafe'):
            module.verify(self.ipa, self.receipt)

    def test_exact_inherited_marker_is_allowed_without_altering_signed_code(self):
        marker = b'und3fined'
        self.save_delivery(extra=('Payload/decrypt.day', marker))
        result = module.verify(self.ipa, self.receipt)
        self.assertEqual(result['independently_verified']['inherited_outside_app_files_verified'], [{
            'path': 'Payload/decrypt.day', 'bytes': 9,
            'sha256': '15218e74cef5d8df7e631ab2a31fdb8bde28976252f984231cf410630410696e'}])
        self.assertEqual(result['independently_verified']['signed_macho_file_count'], 6)

    def test_same_length_inherited_marker_mutation_is_rejected(self):
        self.save_delivery(extra=('Payload/decrypt.day', b'und3finez'))
        with self.assertRaisesRegex(ValueError, 'marker SHA256 mismatch'):
            module.verify(self.ipa, self.receipt)

    def test_inherited_marker_wrong_length_is_rejected(self):
        for marker in (b'und3fine', b'und3fined\n'):
            with self.subTest(length=len(marker)):
                self.save_delivery(extra=('Payload/decrypt.day', marker))
                with self.assertRaisesRegex(ValueError, 'marker length mismatch'):
                    module.verify(self.ipa, self.receipt)

    def test_unknown_outside_app_files_remain_rejected(self):
        for name in ('Payload/decrypt.day.extra', 'Payload/Decrypt.day', 'decrypt.day', 'Payload/other'):
            with self.subTest(name=name):
                self.save_delivery(extra=(name, b'und3fined'))
                with self.assertRaisesRegex(ValueError, 'Unexpected files outside the root application'):
                    module.verify(self.ipa, self.receipt)

    def test_receipt_hash_mismatch_is_rejected(self):
        self.save_delivery()
        receipt = json.loads(self.receipt.read_text())
        receipt['sha256'] = '0' * 64
        self.receipt.write_text(json.dumps(receipt))
        with self.assertRaisesRegex(ValueError, 'SHA256 differs'):
            module.verify(self.ipa, self.receipt)

    def test_receipt_keeps_distinct_input_provenance_and_build_pins(self):
        from unittest.mock import patch
        build_commit = 'b' * 40
        with patch.object(module, 'SOURCE_COMMIT', build_commit):
            self.save_delivery()
            result = module.verify(self.ipa, self.receipt)
            self.assertEqual(result['source_commit'], build_commit)
            self.assertEqual(result['input_source_commit'], module.INPUT_SOURCE_COMMIT)
            receipt = json.loads(self.receipt.read_text())
            receipt['input_source_commit'] = build_commit
            self.receipt.write_text(json.dumps(receipt))
            with self.assertRaisesRegex(ValueError, 'source/input differs'):
                module.verify(self.ipa, self.receipt)

    def test_receipt_missing_input_provenance_or_old_build_is_rejected(self):
        from unittest.mock import patch
        self.save_delivery()
        with patch.object(module, 'SOURCE_COMMIT', 'b' * 40), self.assertRaisesRegex(ValueError, 'source/input differs'):
            module.verify(self.ipa, self.receipt)
        self.save_delivery()
        receipt = json.loads(self.receipt.read_text())
        receipt.pop('input_source_commit')
        self.receipt.write_text(json.dumps(receipt))
        with self.assertRaisesRegex(ValueError, 'source/input differs'):
            module.verify(self.ipa, self.receipt)

    def test_shared_wildcard_profile_is_concretized_for_all_five_bundles(self):
        for grant in ('*', 'com.ayato.*'):
            with self.subTest(grant=grant):
                payload, profiles = self.make_payload(grant=grant)
                self.save_delivery(payload=payload, profiles=profiles, wildcard=True)
                result = module.verify(self.ipa, self.receipt)
                verified = result['independently_verified']
                self.assertEqual(verified['distinct_profile_count'], 1)
                self.assertTrue(all(profile['application_identifier_kind'] == 'wildcard'
                                    for profile in verified['profiles']))
                self.assertTrue(all(profile['xml_entitlements_match_concrete_profile']
                                    for profile in verified['profiles']))
                self.assertNotIn(DEVICE, json.dumps(result))

    def test_wildcard_profile_cannot_grant_another_scope_or_embedded_wildcard(self):
        for grant in ('com.another.*', 'com.*.bereal493'):
            with self.subTest(grant=grant):
                payload, profiles = self.make_payload(grant=grant)
                self.save_delivery(payload=payload, profiles=profiles, wildcard=True)
                with self.assertRaisesRegex(ValueError, 'Profile application identity mismatch'):
                    module.verify(self.ipa, self.receipt)

    def test_actual_signed_wildcard_entitlements_are_rejected(self):
        payload, profiles = self.make_payload(grant='com.ayato.*', signed_wildcards=True)
        self.save_delivery(payload=payload, profiles=profiles, wildcard=True)
        with self.assertRaisesRegex(ValueError, 'Signed XML entitlements differ'):
            module.verify(self.ipa, self.receipt)

    def test_profile_only_apple_token_is_omitted_from_valid_signed_rights(self):
        payload, profiles = self.make_payload(profile_keychain=[TEAM + '.*', 'com.apple.token'])
        self.save_delivery(payload=payload, profiles=profiles)
        result = module.verify(self.ipa, self.receipt)
        self.assertTrue(all(profile['xml_entitlements_match_concrete_profile']
                            for profile in result['independently_verified']['profiles']))

    def test_cryptographically_signed_apple_token_claim_is_rejected(self):
        payload, profiles = self.make_payload(profile_keychain=[TEAM + '.*', 'com.apple.token'], signed_token=True)
        self.save_delivery(payload=payload, profiles=profiles)
        with self.assertRaisesRegex(ValueError, 'Signed XML entitlements differ'):
            module.verify(self.ipa, self.receipt)

    def test_profile_with_only_apple_token_is_rejected(self):
        payload, profiles = self.make_payload(profile_keychain=['com.apple.token'])
        self.save_delivery(payload=payload, profiles=profiles)
        with self.assertRaisesRegex(ValueError, 'no scoped app keychain grant'):
            module.verify(self.ipa, self.receipt)

    def test_profile_other_foreign_keychain_grant_is_still_rejected(self):
        for foreign in ('com.apple.token.child', TEAM + '.com.other.app'):
            with self.subTest(foreign=foreign):
                payload, profiles = self.make_payload(profile_keychain=[TEAM + '.*', 'com.apple.token', foreign])
                self.save_delivery(payload=payload, profiles=profiles)
                with self.assertRaisesRegex(ValueError, 'Unexpected keychain entitlement scope'):
                    module.verify(self.ipa, self.receipt)

    def test_wildcard_profile_requires_matching_ci_selection_and_profile_count(self):
        payload, profiles = self.make_payload(grant='com.ayato.*')
        self.save_delivery(payload=payload, profiles=profiles)
        with self.assertRaisesRegex(ValueError, 'Wildcard profile selection differs'):
            module.verify(self.ipa, self.receipt)
        self.save_delivery(payload=payload, profiles=profiles, wildcard=True)
        receipt = json.loads(self.receipt.read_text())
        receipt['distinct_profile_count'] = 5
        self.receipt.write_text(json.dumps(receipt))
        with self.assertRaisesRegex(ValueError, 'distinct profile count mismatch'):
            module.verify(self.ipa, self.receipt)


if __name__ == '__main__':
    unittest.main()
