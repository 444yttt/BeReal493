"""Post-allowance keychain patch boundaries, including optional exact-input verification."""
import copy
import hashlib
import importlib.util
import os
from pathlib import Path
import struct
import unittest
from unittest.mock import patch


SCRIPTS = Path(__file__).resolve().parents[1] / 'scripts'
SPEC = importlib.util.spec_from_file_location('post_storage_patch', SCRIPTS / 'post_storage_patch.py')
module = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(module)


class PostStoragePatchTests(unittest.TestCase):
    def setUp(self):
        self.start = 128
        self.size = module.FACTORY_CONTEXT_SIZE
        self.targets = tuple(
            (self.start + offset - module.FACTORY_CONTEXT_OFFSET, expected, replacement, register)
            for offset, expected, replacement, register in module.PATCHES)
        data = bytearray(384)
        struct.pack_into('<8I', data, 0, 0xFEEDFACF, 0x0100000C, 0, 2, 1, 24, 0, 0)
        struct.pack_into('<6I', data, 32, 0x2C, 24, 0, 0, 0, 0)
        data[self.start:self.start + self.size] = module.ORIGINAL_FACTORY_CONTEXT_BYTES
        self.after_auth = bytes(data)
        changed = bytearray(data)
        for offset, _, replacement, _ in self.targets:
            changed[offset:offset + 4] = replacement
        self.patched = bytes(changed)
        self.bindings = {
            'AUTH_PATCHED_MAIN_SHA256': hashlib.sha256(self.after_auth).hexdigest(),
            'FACTORY_CONTEXT_OFFSET': self.start,
            'PATCHES': self.targets,
        }
        self.scope = patch.multiple(module, **self.bindings)
        self.scope.start()
        self.addCleanup(self.scope.stop)

    def test_exact_input_changes_only_two_final_group_argument_writers(self):
        before = bytes(self.after_auth)
        result = module.patch_after_auth_main(before)
        self.assertEqual(result, self.patched)
        self.assertEqual(before, self.after_auth)
        self.assertEqual(len(result), len(before))
        allowed = {p for offset, _, _, _ in self.targets for p in range(offset, offset + 4)}
        self.assertEqual(sum(len(expected) for _, expected, _, _ in self.targets), 8)
        self.assertTrue(all(before[p] == result[p] for p in range(len(before)) if p not in allowed))
        self.assertIsNone(module.verify_patched_main(result))

    def test_raw_foreign_repeated_partial_and_tampered_inputs_fail_whole_main_pin(self):
        partial = bytearray(self.after_auth)
        offset, _, replacement, _ = self.targets[0]
        partial[offset:offset + 4] = replacement
        tampered = bytearray(self.after_auth)
        tampered[-1] ^= 1
        before_auth = bytearray(self.after_auth)
        before_auth[96] = 1
        for candidate in (b'foreign bytes', bytes(before_auth), self.patched, bytes(partial), bytes(tampered)):
            with self.subTest(digest=hashlib.sha256(candidate).hexdigest()), \
                    self.assertRaisesRegex(ValueError, 'SHA256'):
                module.patch_after_auth_main(candidate)

    def test_bytearray_is_not_accepted_as_mutable_input(self):
        with self.assertRaisesRegex(ValueError, 'must be bytes'):
            module.patch_after_auth_main(bytearray(self.after_auth))

    def test_writer_and_complete_factory_pins_reject_tampering_despite_mocked_file_pin(self):
        for offset, expected_message in ((self.targets[0][0], 'argument writer'),
                                         (self.start + self.size - 4, 'factory context')):
            changed = bytearray(self.after_auth)
            changed[offset] ^= 1
            with self.subTest(offset=offset), \
                    patch.object(module, 'AUTH_PATCHED_MAIN_SHA256', hashlib.sha256(changed).hexdigest()), \
                    self.assertRaisesRegex(ValueError, expected_message):
                module.patch_after_auth_main(bytes(changed))

    def test_arm64_executable_and_single_cryptid_zero_command_are_required(self):
        for offset, value in ((0, 0), (4, 7), (8, 2), (12, 6), (48, 1)):
            changed = bytearray(self.after_auth)
            struct.pack_into('<I', changed, offset, value)
            with self.subTest(field=offset), \
                    patch.object(module, 'AUTH_PATCHED_MAIN_SHA256', hashlib.sha256(changed).hexdigest()), \
                    self.assertRaises(ValueError):
                module.patch_after_auth_main(bytes(changed))

    def test_missing_duplicate_and_malformed_encryption_commands_fail(self):
        variants = []
        missing = bytearray(self.after_auth)
        struct.pack_into('<I', missing, 32, 0x1B)
        variants.append(missing)
        duplicate = bytearray(self.after_auth)
        struct.pack_into('<II', duplicate, 16, 2, 48)
        struct.pack_into('<6I', duplicate, 56, 0x2C, 24, 0, 0, 0, 0)
        variants.append(duplicate)
        malformed = bytearray(self.after_auth)
        struct.pack_into('<I', malformed, 36, 4)
        variants.append(malformed)
        for changed in variants:
            with self.subTest(header=hashlib.sha256(changed[:80]).hexdigest()), \
                    patch.object(module, 'AUTH_PATCHED_MAIN_SHA256', hashlib.sha256(changed).hexdigest()), \
                    self.assertRaises(ValueError):
                module.patch_after_auth_main(bytes(changed))

    def test_signed_verification_allows_header_and_signature_changes_outside_factory(self):
        changed = bytearray(self.patched)
        changed[16:20] = struct.pack('<I', 2)
        changed[-16:] = b'new-CMS-fixture!!'
        self.assertIsNone(module.verify_patched_main(bytes(changed)))

    def test_signed_verification_rejects_either_original_or_tampered_writer(self):
        for offset, expected, _, register in self.targets:
            changed = bytearray(self.patched)
            changed[offset:offset + 4] = expected
            with self.subTest(register=register), self.assertRaisesRegex(ValueError, 'argument writer'):
                module.verify_patched_main(bytes(changed))
        with self.assertRaisesRegex(ValueError, 'argument writer'):
            module.verify_patched_main(self.after_auth)

    def test_signed_verification_binds_full_context_and_input_type(self):
        changed = bytearray(self.patched)
        changed[self.start + self.size - 4] ^= 1
        for candidate in (bytes(changed), self.patched[:self.start], bytearray(self.patched)):
            with self.subTest(type=type(candidate).__name__), self.assertRaises(ValueError):
                module.verify_patched_main(candidate)

    def test_receipt_is_independent_complete_and_does_not_claim_policy_bypasses(self):
        receipt = module.public_receipt()
        self.assertEqual(receipt['auth_patched_input_main_sha256'], self.bindings['AUTH_PATCHED_MAIN_SHA256'])
        self.assertEqual(receipt['patch_instruction_count'], 2)
        self.assertEqual(receipt['patch_span_bytes'], 8)
        self.assertEqual(receipt['factory_context']['bytes'], self.size)
        for key in ('security_api_interception', 'foreign_keychain_access_granted',
                    'quota_checks_bypassed', 'timing_checks_bypassed'):
            self.assertIs(receipt[key], False)
        snapshot = copy.deepcopy(receipt)
        receipt['patches'][0]['file_offset'] = -1
        self.assertEqual(module.public_receipt(), snapshot)


class ExactOriginalPostStoragePatchTests(unittest.TestCase):
    @unittest.skipUnless(os.environ.get('BEREAL493_ORIGINAL_MAIN'), 'Exact original main path not supplied')
    def test_existing_auth_then_post_storage_on_exact_original(self):
        original = Path(os.environ['BEREAL493_ORIGINAL_MAIN']).read_bytes()
        self.assertEqual(hashlib.sha256(original).hexdigest(), module.ORIGINAL_MAIN_SHA256)
        spec = importlib.util.spec_from_file_location('exact_auth_patch', SCRIPTS / 'auth_keychain_patch.py')
        auth = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(auth)
        after_auth = auth.patch_original_main(original)
        self.assertEqual(hashlib.sha256(after_auth).hexdigest(), module.AUTH_PATCHED_MAIN_SHA256)
        result = module.patch_after_auth_main(after_auth)
        module.verify_patched_main(result)
        auth.verify_patched_main(result)
        cursor = 0
        for offset, expected, replacement, _ in module.PATCHES:
            self.assertEqual(after_auth[cursor:offset], result[cursor:offset])
            self.assertEqual(after_auth[offset:offset + 4], expected)
            self.assertEqual(result[offset:offset + 4], replacement)
            cursor = offset + 4
        self.assertEqual(after_auth[cursor:], result[cursor:])
        with self.assertRaisesRegex(ValueError, 'SHA256'):
            module.patch_after_auth_main(original)


if __name__ == '__main__':
    unittest.main()
