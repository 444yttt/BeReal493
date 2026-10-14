"""Canonical synthetic main fixtures; no original app or auth values needed."""
import copy
import hashlib
import importlib.util
from pathlib import Path
import struct
import unittest
from unittest.mock import patch


SPEC = importlib.util.spec_from_file_location('auth_keychain_patch',
    Path(__file__).resolve().parents[1] / 'scripts' / 'auth_keychain_patch.py')
module = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(module)


class AuthKeychainPatchTests(unittest.TestCase):
    def setUp(self):
        self.start, self.size = 128, 80
        self.targets = ((176, bytes.fromhex('42a8ecf2'), bytes.fromhex('020080d2'), 'x2'),
                        (188, bytes.fromhex('0380fdf2'), bytes.fromhex('030080d2'), 'x3'))
        data = bytearray(320)
        struct.pack_into('<8I', data, 0, 0xFEEDFACF, 0x0100000C, 0, 2, 1, 24, 0, 0)
        struct.pack_into('<6I', data, 32, 0x2C, 24, 0, 0, 0, 0)
        data[self.start:self.start + self.size] = bytes.fromhex('1f2003d5') * 20
        for offset, expected, _, _ in self.targets:
            data[offset:offset + 4] = expected
        self.original = bytes(data)
        changed = bytearray(data)
        for offset, _, replacement, _ in self.targets:
            changed[offset:offset + 4] = replacement
        self.patched = bytes(changed)
        self.bindings = {
            'ORIGINAL_MAIN_SHA256': hashlib.sha256(self.original).hexdigest(),
            'FACTORY_CONTEXT_OFFSET': self.start, 'FACTORY_CONTEXT_SIZE': self.size,
            'ORIGINAL_CONTEXT_SHA256': hashlib.sha256(self.original[self.start:self.start + self.size]).hexdigest(),
            'PATCHED_CONTEXT_SHA256': hashlib.sha256(self.patched[self.start:self.start + self.size]).hexdigest(),
            'PATCHES': self.targets,
        }
        self.scope = patch.multiple(module, **self.bindings)
        self.scope.start()
        self.addCleanup(self.scope.stop)

    def test_canonical_original_changes_only_two_four_byte_instruction_spans(self):
        original_copy = bytes(self.original)
        result = module.patch_original_main(self.original)
        self.assertEqual(result, self.patched)
        self.assertEqual(self.original, original_copy)
        self.assertEqual(len(result), len(self.original))
        spans = {index for offset, _, _, _ in self.targets for index in range(offset, offset + 4)}
        self.assertEqual(sum(len(expected) for _, expected, _, _ in self.targets), 8)
        self.assertTrue(all(result[index] == self.original[index] for index in range(len(result)) if index not in spans))
        self.assertIsNone(module.verify_patched_main(result))

    def test_foreign_repeated_partial_and_arbitrary_tampered_inputs_are_rejected(self):
        partial = bytearray(self.original)
        offset, _, replacement, _ = self.targets[0]
        partial[offset:offset + 4] = replacement
        tampered = bytearray(self.original); tampered[-1] ^= 1
        for candidate in (b'foreign bytes', self.patched, bytes(partial), bytes(tampered)):
            with self.subTest(length=len(candidate)), self.assertRaisesRegex(ValueError, 'SHA256'):
                module.patch_original_main(candidate)

    def test_target_writer_mismatch_is_rejected_even_with_mocked_whole_file_pin(self):
        changed = bytearray(self.original); changed[self.targets[0][0]] ^= 1
        with patch.object(module, 'ORIGINAL_MAIN_SHA256', hashlib.sha256(changed).hexdigest()), \
            self.assertRaisesRegex(ValueError, 'argument writer'):
            module.patch_original_main(bytes(changed))

    def test_factory_context_mismatch_is_rejected_even_when_both_writers_match(self):
        changed = bytearray(self.original); changed[self.start] ^= 1
        with patch.object(module, 'ORIGINAL_MAIN_SHA256', hashlib.sha256(changed).hexdigest()), \
            self.assertRaisesRegex(ValueError, 'context'):
            module.patch_original_main(bytes(changed))

    def test_arm64_executable_and_cryptid_zero_are_required(self):
        for offset, value in ((0, 0), (4, 7), (8, 2), (12, 6), (48, 1)):
            changed = bytearray(self.original); struct.pack_into('<I', changed, offset, value)
            with self.subTest(field=offset), \
                patch.object(module, 'ORIGINAL_MAIN_SHA256', hashlib.sha256(changed).hexdigest()), \
                self.assertRaises(ValueError):
                module.patch_original_main(bytes(changed))

    def test_missing_duplicate_or_malformed_encryption_commands_are_rejected(self):
        variants = []
        missing = bytearray(self.original); struct.pack_into('<I', missing, 32, 0x1B); variants.append(missing)
        duplicate = bytearray(self.original); struct.pack_into('<II', duplicate, 16, 2, 48)
        struct.pack_into('<6I', duplicate, 56, 0x2C, 24, 0, 0, 0, 0); variants.append(duplicate)
        malformed = bytearray(self.original); struct.pack_into('<I', malformed, 36, 4); variants.append(malformed)
        for changed in variants:
            with self.subTest(header=hashlib.sha256(changed[:80]).hexdigest()), \
                patch.object(module, 'ORIGINAL_MAIN_SHA256', hashlib.sha256(changed).hexdigest()), \
                self.assertRaises(ValueError):
                module.patch_original_main(bytes(changed))

    def test_signed_verification_allows_header_and_signature_changes_outside_factory(self):
        changed = bytearray(self.patched)
        changed[16:20] = bytes.fromhex('02000000')
        changed[-16:] = b'new-CMS-fixture!!'
        self.assertIsNone(module.verify_patched_main(bytes(changed)))

    def test_signed_verification_requires_both_exact_replacement_instructions(self):
        for target in self.targets:
            changed = bytearray(self.patched)
            offset, expected, _, _ = target
            changed[offset:offset + 4] = expected
            with self.subTest(register=target[3]), self.assertRaisesRegex(ValueError, 'argument writer'):
                module.verify_patched_main(bytes(changed))
        with self.assertRaisesRegex(ValueError, 'argument writer'):
            module.verify_patched_main(self.original)

    def test_signed_verification_rejects_modified_context_missing_or_nonbytes_input(self):
        changed = bytearray(self.patched); changed[self.start + 8] ^= 1
        for candidate in (bytes(changed), self.patched[:self.start], bytearray(self.patched)):
            with self.subTest(type=type(candidate).__name__), self.assertRaises(ValueError):
                module.verify_patched_main(candidate)

    def test_public_receipt_is_deterministic_and_independent_of_caller_mutations(self):
        receipt = module.public_receipt()
        self.assertEqual(receipt['patch_span_bytes'], 8)
        self.assertEqual(receipt['patch_instruction_count'], 2)
        self.assertEqual(receipt['original_main_sha256'], self.bindings['ORIGINAL_MAIN_SHA256'])
        self.assertFalse(receipt['security_api_interception'])
        self.assertFalse(receipt['foreign_keychain_access_granted'])
        snapshot = copy.deepcopy(receipt)
        receipt['patches'][0]['file_offset'] = -1
        self.assertEqual(module.public_receipt(), snapshot)


if __name__ == '__main__':
    unittest.main()
