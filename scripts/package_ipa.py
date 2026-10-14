#!/usr/bin/env python3
"""Inject the compiled adapter without changing payload offsets; output requires device signing."""
import argparse
import hashlib
import importlib.util
import json
import plistlib
import struct
import zipfile
from pathlib import Path, PurePosixPath

ORIGINAL_SHA256 = 'e7d77665740c61f2b0d6eae21cb6052acd2add364db3f6b5fc9ef9198ac31cbc'
DYLIB_PATH = '@executable_path/Frameworks/CameraRollAdapter.dylib'

_auth_spec = importlib.util.spec_from_file_location('bereal_auth_patch', Path(__file__).with_name('auth_keychain_patch.py'))
AUTH_PATCH = importlib.util.module_from_spec(_auth_spec)
_auth_spec.loader.exec_module(AUTH_PATCH)


def load_commands(data):
    if len(data) < 32 or struct.unpack_from('<I', data)[0] != 0xFEEDFACF:
        raise ValueError('Expected a little-endian 64-bit Mach-O')
    if struct.unpack_from('<I', data, 4)[0] != 0x0100000C:
        raise ValueError('Only ARM64 Mach-O is supported')
    count, size = struct.unpack_from('<II', data, 16)
    end = 32 + size
    if end > len(data):
        raise ValueError('Truncated load commands')
    commands = []
    offset = 32
    for _ in range(count):
        if offset + 8 > end:
            raise ValueError('Truncated load command')
        command, length = struct.unpack_from('<II', data, offset)
        if length < 8 or length % 8 or offset + length > end:
            raise ValueError('Invalid load command length')
        commands.append((command, data[offset:offset + length]))
        offset += length
    if offset != end:
        raise ValueError('Load command count and size disagree')
    return commands, end


def rebuild(data, dependency=None):
    commands, previous_end = load_commands(data)
    first_payload = len(data)
    kept = []
    for command, raw in commands:
        if command == 0x2C and struct.unpack_from('<I', raw, 16)[0] != 0:
            raise ValueError('Encrypted executable cannot be modified')
        if command == 0x19:
            if len(raw) < 72:
                raise ValueError('Truncated segment command')
            count = struct.unpack_from('<I', raw, 64)[0]
            if 72 + count * 80 > len(raw):
                raise ValueError('Truncated section table')
            for i in range(count):
                section = 72 + i * 80
                size = struct.unpack_from('<Q', raw, section + 40)[0]
                offset = struct.unpack_from('<I', raw, section + 48)[0]
                flags = struct.unpack_from('<I', raw, section + 64)[0] & 0xFF
                if size and offset and flags not in (1, 0xC, 0x12):
                    first_payload = min(first_payload, offset)
        if command == 0xC and dependency:
            offset = struct.unpack_from('<I', raw, 8)[0]
            name = raw[offset:].split(b'\0', 1)[0].decode()
            if name == dependency:
                raise ValueError('Adapter is already injected')
        if command != 0x1D:  # remove stale LC_CODE_SIGNATURE
            kept.append(raw)
    if dependency:
        name = dependency.encode() + b'\0'
        length = (24 + len(name) + 7) & ~7
        kept.append(struct.pack('<6I', 0xC, length, 24, 0, 0x10000, 0x10000) + name + b'\0' * (length - 24 - len(name)))
    table = b''.join(kept)
    new_end = 32 + len(table)
    if new_end > first_payload or previous_end > first_payload:
        raise ValueError('Insufficient header space; refusing to move payload offsets')
    if new_end > previous_end and any(data[previous_end:new_end]):
        raise ValueError('Header padding is not empty')
    result = bytearray(data)
    struct.pack_into('<II', result, 16, len(kept), len(table))
    result[32:max(new_end, previous_end)] = table + b'\0' * (max(new_end, previous_end) - new_end)
    if result[first_payload:] != data[first_payload:]:
        raise AssertionError('Mach-O payload bytes changed unexpectedly')
    return bytes(result)


def package(source, library, output):
    source, library, output = map(Path, (source, library, output))
    if source.resolve() == output.resolve():
        raise ValueError('Original IPA must not be overwritten')
    with source.open('rb') as stream:
        if hashlib.file_digest(stream, 'sha256').hexdigest() != ORIGINAL_SHA256:
            raise ValueError('Source is not the verified user-supplied IPA')
    adapter = rebuild(library.read_bytes())
    with zipfile.ZipFile(source) as archive:
        names = archive.namelist()
        if len(names) != len(set(names)):
            raise ValueError('Duplicate archive paths')
        for name in names:
            path = PurePosixPath(name)
            if path.is_absolute() or '..' in path.parts:
                raise ValueError('Unsafe archive path')
        manifest = 'Payload/BeReal.app/Info.plist'
        info = plistlib.loads(archive.read(manifest))
        if (info.get('CFBundleIdentifier'), info.get('CFBundleShortVersionString'), info.get('CFBundleVersion')) != ('AlexisBarreyat.BeReal', '4.93.0', '23026'):
            raise ValueError('Unexpected application identity or version')
        main_path = 'Payload/BeReal.app/' + info['CFBundleExecutable']
        main = rebuild(AUTH_PATCH.patch_original_main(archive.read(main_path)), DYLIB_PATH)
        library_path = 'Payload/BeReal.app/Frameworks/CameraRollAdapter.dylib'
        if library_path in names:
            raise ValueError('Adapter already exists')
        output.parent.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(output, 'w', compression=zipfile.ZIP_DEFLATED, compresslevel=6) as target:
            for item in archive.infolist():
                if '/_CodeSignature/' in item.filename or item.filename.endswith('/embedded.mobileprovision'):
                    continue
                data = main if item.filename == main_path else archive.read(item)
                target.writestr(item, data)
            item = zipfile.ZipInfo(library_path)
            item.create_system = 3
            item.external_attr = 0o100755 << 16
            item.compress_type = zipfile.ZIP_DEFLATED
            target.writestr(item, adapter)
    with zipfile.ZipFile(output) as archive:
        commands, _ = load_commands(archive.read(main_path))
        dependency_count = sum(command == 0xC and DYLIB_PATH.encode() + b'\0' in raw for command, raw in commands)
        if dependency_count != 1 or any(command == 0x1D for command, _ in commands):
            raise ValueError('Output load-command verification failed')
        AUTH_PATCH.verify_patched_main(archive.read(main_path))
        if archive.testzip() is not None:
            raise ValueError('Output ZIP verification failed')
    with output.open('rb') as stream:
        digest = hashlib.file_digest(stream, 'sha256').hexdigest()
    return {'file': output.name, 'sha256': digest, 'input_sha256': ORIGINAL_SHA256,
            'auth_keychain_patch': AUTH_PATCH.public_receipt(),
            'signature': 'unsigned; full nested-code signing and device provisioning required',
            'adapter': 'implemented; compiled; no device execution or posting test performed'}


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('source'); parser.add_argument('library'); parser.add_argument('output')
    options = parser.parse_args()
    print(json.dumps(package(options.source, options.library, options.output), indent=2))
