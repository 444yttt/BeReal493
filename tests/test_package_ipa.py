import importlib.util
import struct
import unittest
from pathlib import Path

spec = importlib.util.spec_from_file_location('package_ipa', Path(__file__).parents[1] / 'scripts/package_ipa.py')
module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)


def image(payload_offset=512, encrypted=False):
    section = bytearray(80)
    section[:6] = b'__text'
    struct.pack_into('<QQI', section, 32, 0x100000000 + payload_offset, 8, payload_offset)
    segment = bytearray(72)
    struct.pack_into('<II', segment, 0, 0x19, 152)
    struct.pack_into('<I', segment, 64, 1)
    crypt = struct.pack('<6I', 0x2C, 24, payload_offset, 8, int(encrypted), 0)
    signature = struct.pack('<4I', 0x1D, 16, payload_offset + 8, 8)
    commands = bytes(segment + section) + crypt + signature
    header = struct.pack('<8I', 0xFEEDFACF, 0x0100000C, 0, 2, 3, len(commands), 0, 0)
    return (header + commands).ljust(payload_offset, b'\0') + b'PAYLOAD!' + b'SIGNATURE'


class PackageTest(unittest.TestCase):
    def test_inject_preserves_payload_and_removes_signature(self):
        original = image()
        modified = module.rebuild(original, module.DYLIB_PATH)
        self.assertEqual(original[512:], modified[512:])
        commands, _ = module.load_commands(modified)
        self.assertFalse(any(c == 0x1D for c, r in commands))
        self.assertEqual(sum(c == 0xC for c, r in commands), 1)
        with self.assertRaises(ValueError): module.rebuild(modified, module.DYLIB_PATH)

    def test_rejects_encrypted_image(self):
        with self.assertRaises(ValueError): module.rebuild(image(encrypted=True), module.DYLIB_PATH)

    def test_rejects_insufficient_padding(self):
        with self.assertRaises(ValueError): module.rebuild(image(payload_offset=224), module.DYLIB_PATH)

    def test_rejects_nonzero_padding(self):
        original = bytearray(image()); original[225] = 1
        with self.assertRaises(ValueError): module.rebuild(bytes(original), module.DYLIB_PATH)
