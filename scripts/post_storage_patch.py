"""Move the verified native post-allowance storage into this app's keychain.

The LocalStorage singleton passes the original App Group to KeychainAccess.
The re-signed app cannot use that foreign group, so native allowance reads
fall back to zero and writes fail. Omit only that factory's explicit group.
Native server values, timing checks, service and accessibility stay intact.
The same singleton also stores the stable device ID. Security APIs are not
intercepted and no access to another app's items is granted.
"""
import hashlib
import struct


ORIGINAL_MAIN_SHA256 = 'd64203bfef02feb41680a43224762e8e5be2f9723e6f62924d8d5bfc2d1b2cd6'
# Mandatory input order: exact original -> existing auth patch -> this patch
# -> load-command rebuilding/injection -> signing.
AUTH_PATCHED_MAIN_SHA256 = '922e252e763e8061ab8a154f653ce0f390c332a17bebd49bd65237fc33db5a7e'
FACTORY_CONTEXT_OFFSET = 0x8C7F9C
FACTORY_CONTEXT_SIZE = 0x7C
ORIGINAL_CONTEXT_SHA256 = 'd8c6f971527dc78e863cd2c044c9d611c7c3e6407c99b4f5e10702f834544e5e'
PATCHED_CONTEXT_SHA256 = 'a6d2908e2ae2c38d39d1f62c4b34a322ad733f15e3aa35bb814e7edbc2362c7a'
# Limited instruction context for independent synthetic verification fixtures;
# this is code, not a keychain value, service string or original IPA payload.
ORIGINAL_FACTORY_CONTEXT_BYTES = bytes.fromhex(
    'f44fbea9fd7b01a9fd430091000080d24b540094f40300aa685d01d008c109910'
    '88100d1e24c8ed2e2adaef202cec5f242a8ecf243aa8cd2238cadf20380fdf2'
    '010141b2600280d20000faf2b61b0094f40300aa20008052151d0094f30300aa'
    'e00314aa444ca294a8e001d013e907f9fd7b41a9f44fc2a8c0035fd6')
PATCHES = (
    (0x8C7FCC, bytes.fromhex('42a8ecf2'), bytes.fromhex('020080d2'), 'x2'),
    (0x8C7FD8, bytes.fromhex('0380fdf2'), bytes.fromhex('030080d2'), 'x3'),
)


def _require(condition, message):
    if not condition:
        raise ValueError(message)


def _check_arm64_main(data):
    _require(len(data) >= 32, 'Post storage input has no complete Mach-O header')
    magic, cpu, subtype, filetype, count, commands_size, _, _ = struct.unpack_from('<8I', data)
    _require((magic, cpu, subtype, filetype) == (0xFEEDFACF, 0x0100000C, 0, 2),
             'Post storage input must be the pinned ARM64 executable')
    end = 32 + commands_size
    _require(0 < count <= commands_size // 8 and end <= len(data),
             'Post storage input load commands are invalid')
    cursor, cryptids = 32, []
    for _ in range(count):
        _require(cursor + 8 <= end, 'Post storage load command is truncated')
        command, size = struct.unpack_from('<II', data, cursor)
        _require(size >= 8 and size % 4 == 0 and cursor + size <= end,
                 'Post storage load command size is invalid')
        if command in (0x21, 0x2C):
            _require(size >= (24 if command == 0x2C else 20),
                     'Post storage encryption command is truncated')
            cryptids.append(struct.unpack_from('<I', data, cursor + 16)[0])
        cursor += size
    _require(cursor == end, 'Post storage load command table differs from its size')
    _require(cryptids == [0], 'Post storage input must contain exactly one cryptid-zero command')


def _check_factory(data, *, patched):
    _require(isinstance(data, bytes), 'Post storage main input must be bytes')
    start = FACTORY_CONTEXT_OFFSET
    end = start + FACTORY_CONTEXT_SIZE
    _require(0 <= start < end <= len(data), 'Post storage factory context is missing')
    for offset, expected, replacement, _ in PATCHES:
        _require(len(expected) == len(replacement) == 4 and start <= offset <= end - 4,
                 'Post storage patch binding is invalid')
        _require(data[offset:offset + 4] == (replacement if patched else expected),
                 'Post storage argument writer differs from its pinned bytes')
    expected_digest = PATCHED_CONTEXT_SHA256 if patched else ORIGINAL_CONTEXT_SHA256
    _require(hashlib.sha256(data[start:end]).hexdigest() == expected_digest,
             'Post storage factory context differs from its pinned hash')


def patch_after_auth_main(data: bytes) -> bytes:
    """Apply only to the exact main returned by the mandatory existing auth patch."""
    _require(isinstance(data, bytes), 'Post storage main input must be bytes')
    _require(hashlib.sha256(data).hexdigest() == AUTH_PATCHED_MAIN_SHA256,
             'Post storage input SHA256 differs from the pinned main after authentication patch')
    _check_arm64_main(data)
    _check_factory(data, patched=False)
    output = bytearray(data)
    for offset, _, replacement, _ in PATCHES:
        output[offset:offset + 4] = replacement
    result = bytes(output)
    _check_factory(result, patched=True)
    cursor = 0
    for offset, expected, _, _ in sorted(PATCHES):
        _require(data[cursor:offset] == result[cursor:offset],
                 'Post storage patch modified unrelated bytes')
        cursor = offset + len(expected)
    _require(len(result) == len(data) and data[cursor:] == result[cursor:],
             'Post storage patch modified unrelated bytes')
    return result


def verify_patched_main(data: bytes) -> None:
    """Require the complete patched factory after injection/signing changes headers."""
    _check_factory(data, patched=True)


def public_receipt() -> dict:
    """Return independent mandatory evidence with no keychain contents or identifiers."""
    return {
        'version': 1,
        'purpose': 'native_post_allowance_and_stable_device_storage_own_app_keychain',
        'policy': 'Omit the explicit foreign App Group only in the verified LocalStorage singleton factory; use the permitted default app keychain group.',
        'original_main_sha256': ORIGINAL_MAIN_SHA256,
        'auth_patched_input_main_sha256': AUTH_PATCHED_MAIN_SHA256,
        'architecture': 'ARM64',
        'original_cryptid': 0,
        'patch_instruction_count': len(PATCHES),
        'patch_span_bytes': sum(len(expected) for _, expected, _, _ in PATCHES),
        'patches': [
            {'file_offset': offset, 'expected_hex': expected.hex(),
             'replacement_hex': replacement.hex(), 'argument_register': register,
             'replacement_operation': 'mov ' + register + ', #0'}
            for offset, expected, replacement, register in PATCHES
        ],
        'factory_context': {
            'file_offset': FACTORY_CONTEXT_OFFSET, 'bytes': FACTORY_CONTEXT_SIZE,
            'original_sha256': ORIGINAL_CONTEXT_SHA256, 'patched_sha256': PATCHED_CONTEXT_SHA256,
        },
        'nil_encoding': 'Swift.Optional<String>.none: x2=0 and x3=0; the existing query builder omits kSecAttrAccessGroup.',
        'security_api_interception': False,
        'foreign_keychain_access_granted': False,
        'quota_checks_bypassed': False,
        'timing_checks_bypassed': False,
    }
