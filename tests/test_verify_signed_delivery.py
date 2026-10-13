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
        cls.payload, cls.profile_receipts = {}, []
        now = dt.datetime.now(dt.timezone.utc).replace(tzinfo=None, microsecond=0)
        for suffix in module.SUFFIXES:
            identifier = module.ROOT_ID + suffix
            bundle = 'Payload/BeReal.app' + ('' if not suffix else '/PlugIns/' + suffix[1:] + '.appex')
            info = plistlib.dumps({'CFBundleIdentifier': identifier, 'CFBundleExecutable': 'Executable',
                                   'CFBundleShortVersionString': '4.93.0', 'CFBundleVersion': '23026'})
            resources = plistlib.dumps({'files': {}})
            entitlements = {'application-identifier': TEAM + '.' + identifier,
                            'com.apple.developer.team-identifier': TEAM, 'get-task-allow': False,
                            'keychain-access-groups': [TEAM + '.*']}
            profile = {'UUID': str(uuid.uuid4()), 'Entitlements': entitlements,
                       'TeamIdentifier': [TEAM], 'ApplicationIdentifierPrefix': [TEAM],
                       'ProvisionedDevices': [DEVICE], 'DeveloperCertificates': [cls.der],
                       'CreationDate': now - dt.timedelta(days=1),
                       'ExpirationDate': now + dt.timedelta(days=1)}
            concrete = module.concrete_entitlements(profile, identifier)
            cls.payload[bundle + '/Info.plist'] = info
            cls.payload[bundle + '/_CodeSignature/CodeResources'] = resources
            cls.payload[bundle + '/embedded.mobileprovision'] = cls.cms(plistlib.dumps(profile), attached=True)
            cls.payload[bundle + '/Executable'] = cls.executable(
                identifier, concrete, info, resources, adapter=not suffix)
            cls.profile_receipts.append({'bundle_identifier': identifier, 'profile_uuid': profile['UUID'],
                                         'expiration_date': profile['ExpirationDate'].isoformat() + 'Z',
                                         'entitlement_keys': sorted(concrete)})
        cls.payload['Payload/BeReal.app/Frameworks/CameraRollAdapter.dylib'] = cls.executable('CameraRollAdapter')

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
    def executable(cls, identifier, entitlements=None, info=None, resources=None, adapter=False):
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

    def save_delivery(self, changed=None, extra=None):
        with zipfile.ZipFile(self.ipa, 'w') as archive:
            for name, value in self.payload.items():
                archive.writestr(name, (changed or {}).get(name, value))
            if extra:
                archive.writestr(*extra)
        receipt = {'file': self.ipa.name, 'sha256': module.digest_file(self.ipa),
                   'source_commit': module.SOURCE_COMMIT, 'input_sha256': module.ORIGINAL_SHA,
                   'bundle_identifier': module.ROOT_ID, 'distribution': 'IOS_APP_ADHOC',
                   'registered_device_count': 1, 'provisioned_bundle_count': 5,
                   'signature_verification': ('codesign deep strict passed; each app/extension matched '
                                              'concrete profile entitlements and the approved certificate'),
                   'device_installation': 'not tested', 'posting': 'not tested',
                   'certificate_sha256': hashlib.sha256(self.der).hexdigest(),
                   'profiles': self.profile_receipts}
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

    def test_unsafe_zip_path_is_rejected(self):
        self.save_delivery(extra=('Payload/BeReal.app/../outside', b'unsafe-fixture'))
        with self.assertRaisesRegex(ValueError, 'Unsafe'):
            module.verify(self.ipa, self.receipt)

    def test_receipt_hash_mismatch_is_rejected(self):
        self.save_delivery()
        receipt = json.loads(self.receipt.read_text())
        receipt['sha256'] = '0' * 64
        self.receipt.write_text(json.dumps(receipt))
        with self.assertRaisesRegex(ValueError, 'SHA256 differs'):
            module.verify(self.ipa, self.receipt)


if __name__ == '__main__':
    unittest.main()
