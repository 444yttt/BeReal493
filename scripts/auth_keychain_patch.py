"""Pin a minimal original-main patch to the default app keychain group.

The verified TokenStorage factory passes a foreign App Group as an explicit
KeychainAccess accessGroup. Clear only its two final argument writers. This
omits that query attribute and uses the app's permitted default keychain group;
it does not intercept Security APIs or grant access to another application's
items. No credential, token, user, or keychain service value is exposed here.
"""
import hashlib
import struct


ORIGINAL_MAIN_SHA256 = 'd64203bfef02feb41680a43224762e8e5be2f9723e6f62924d8d5bfc2d1b2cd6'
FACTORY_CONTEXT_OFFSET = 0x26D2754
FACTORY_CONTEXT_SIZE = 0x50
ORIGINAL_CONTEXT_SHA256 = '2123ac2ca5e05ae9fb1cefae62712ffdb82b83c04532c0e9c628be9056c09ebf'
PATCHED_CONTEXT_SHA256 = '302b8c20305d7714d967af26ae82227bdffa6be46ca449a225af47d2e75b0d17'
# Safe instruction context for synthetic signed-delivery fixtures. This is
# machine code, not a credential, service value or original IPA payload.
ORIGINAL_FACTORY_CONTEXT_BYTES = bytes.fromhex(
    'f44fbea9fd7b01a9fd430091000080d25d2a8897f40300aa287100b008811a91'
    '088100d1e24c8ed2e2adaef202cec5f242a8ecf243aa8cd2238cadf20380fdf2'
    '010141b2600280d20000faf2c8f18797')
# File offsets equal offsets from the original main image's 0x100000000 base.
PATCHES = (
    (0x26D2784, bytes.fromhex('42a8ecf2'), bytes.fromhex('020080d2'), 'x2'),
    (0x26D2790, bytes.fromhex('0380fdf2'), bytes.fromhex('030080d2'), 'x3'),
)


def _require(condition, message):
    if not condition:
        raise ValueError(message)


def _check_original_arm64_main(data):
    _require(len(data) >= 32, 'Original main has no complete Mach-O header')
    magic, cpu, subtype, filetype, count, commands_size, _, _ = struct.unpack_from('<8I', data)
    _require((magic, cpu, subtype, filetype) == (0xFEEDFACF, 0x0100000C, 0, 2),
             'Original main must be the pinned ARM64 executable')
    commands_end = 32 + commands_size
    _require(0 < count <= commands_size // 8 and commands_end <= len(data),
             'Original main load commands are invalid')
    cursor, cryptids = 32, []
    for _ in range(count):
        _require(cursor + 8 <= commands_end, 'Original main load command is truncated')
        command, size = struct.unpack_from('<II', data, cursor)
        _require(size >= 8 and size % 4 == 0 and cursor + size <= commands_end,
                 'Original main load command size is invalid')
        if command in (0x21, 0x2C):
            _require(size >= (24 if command == 0x2C else 20), 'Original main encryption command is truncated')
            cryptids.append(struct.unpack_from('<I', data, cursor + 16)[0])
        cursor += size
    _require(cursor == commands_end, 'Original main load command table differs from its size')
    _require(cryptids == [0], 'Original main must contain exactly one cryptid-zero command')


def _check_factory(data, *, patched):
    _require(isinstance(data, bytes), 'Main input must be bytes')
    start, end = FACTORY_CONTEXT_OFFSET, FACTORY_CONTEXT_OFFSET + FACTORY_CONTEXT_SIZE
    _require(0 <= start < end <= len(data), 'Authentication factory context is missing')
    for offset, expected, replacement, _ in PATCHES:
        _require(len(expected) == len(replacement) == 4 and start <= offset <= end - 4,
                 'Authentication patch binding is invalid')
        _require(data[offset:offset + 4] == (replacement if patched else expected),
                 'Authentication argument writer differs from its pinned bytes')
    digest = PATCHED_CONTEXT_SHA256 if patched else ORIGINAL_CONTEXT_SHA256
    _require(hashlib.sha256(data[start:end]).hexdigest() == digest,
             'Authentication factory context differs from its pinned hash')


def patch_original_main(data: bytes) -> bytes:
    """Return a patched copy only for the exact, decrypted original main."""
    _require(isinstance(data, bytes), 'Original main input must be bytes')
    _require(hashlib.sha256(data).hexdigest() == ORIGINAL_MAIN_SHA256,
             'Original main SHA256 differs from the pinned input')
    _check_original_arm64_main(data)
    _check_factory(data, patched=False)
    output = bytearray(data)
    for offset, _, replacement, _ in PATCHES:
        output[offset:offset + 4] = replacement
    result = bytes(output)
    _check_factory(result, patched=True)
    # Preserve every byte outside the two instruction spans, including headers,
    # service setup, initializer call, other functions and signature data.
    cursor = 0
    for offset, expected, _, _ in sorted(PATCHES):
        _require(data[cursor:offset] == result[cursor:offset], 'Authentication patch modified unrelated bytes')
        cursor = offset + len(expected)
    _require(len(result) == len(data) and data[cursor:] == result[cursor:],
             'Authentication patch modified unrelated bytes')
    return result


def verify_patched_main(data: bytes) -> None:
    """Verify the factory after packaging/signing has changed headers/CMS.

    The independent delivery verifier checks those header/signature changes.
    This check binds the entire factory argument setup and its initializer call
    to the expected context, including both exact replacement instructions.
    """
    _check_factory(data, patched=True)


def public_receipt() -> dict:
    """Return deterministic public evidence without authentication values."""
    return {
        'version': 1,
        'purpose': 'authentication_token_storage_own_app_keychain',
        'policy': 'Omit the explicit foreign App Group in the verified TokenStorage factory; use the permitted default app keychain group.',
        'original_main_sha256': ORIGINAL_MAIN_SHA256,
        'architecture': 'ARM64', 'original_cryptid': 0,
        'patch_instruction_count': len(PATCHES), 'patch_span_bytes': sum(len(expected) for _, expected, _, _ in PATCHES),
        'patches': [{'file_offset': offset, 'expected_hex': expected.hex(), 'replacement_hex': replacement.hex(),
                     'argument_register': register, 'replacement_operation': 'mov ' + register + ', #0'}
                    for offset, expected, replacement, register in PATCHES],
        'factory_context': {'file_offset': FACTORY_CONTEXT_OFFSET, 'bytes': FACTORY_CONTEXT_SIZE,
                            'original_sha256': ORIGINAL_CONTEXT_SHA256, 'patched_sha256': PATCHED_CONTEXT_SHA256},
        'nil_encoding': 'Swift.Optional<String>.none: x2=0 and x3=0; query builder skips kSecAttrAccessGroup when the high word is zero.',
        'security_api_interception': False, 'foreign_keychain_access_granted': False,
    }
