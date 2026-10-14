#!/usr/bin/env python3
"""Verify a decrypted BeReal IPA and its CI receipt without executing the app.

Requires Python 3.11+ and OpenSSL. CMS signatures are checked against their
embedded certificates with no CA trust evaluation. This is independent archive,
provisioning, entitlement and signed-code integrity evidence; it is not a local
Apple codesign, installation, launch or posting test.
"""

import argparse
import datetime as dt
import hashlib
import json
from pathlib import Path, PurePosixPath
import plistlib
import re
import ssl
import stat
import struct
import subprocess
import tempfile
import uuid
import zipfile

ORIGINAL_SHA = 'e7d77665740c61f2b0d6eae21cb6052acd2add364db3f6b5fc9ef9198ac31cbc'
INPUT_SOURCE_COMMIT = '1f749cd1b2433d2a32694d5c91849d22f84f429f'
SOURCE_COMMIT = '2ea872b3db210387ece0c5decf9d06543fe3be38'
ROOT_ID = 'com.ayato.bereal493'
SUFFIXES = ('', '.iMessageExtension', '.RealMojiNotificationContentExtension',
            '.NotificationServiceExtension', '.Widgets')
EXPECTED_IDS = {ROOT_ID + suffix for suffix in SUFFIXES}
ADAPTER = '@executable_path/Frameworks/CameraRollAdapter.dylib'
# This non-code marker is inherited byte-for-byte from the SHA-pinned input.
# No other files outside the root application are permitted.
INHERITED_OUTSIDE_FILES = {'Payload/decrypt.day': (
    9, '15218e74cef5d8df7e631ab2a31fdb8bde28976252f984231cf410630410696e')}
MACH_MAGICS = {b'\xce\xfa\xed\xfe', b'\xcf\xfa\xed\xfe',
               b'\xfe\xed\xfa\xce', b'\xfe\xed\xfa\xcf',
               b'\xca\xfe\xba\xbe', b'\xbe\xba\xfe\xca',
               b'\xca\xfe\xba\xbf', b'\xbf\xba\xfe\xca'}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def utc(value):
    require(isinstance(value, dt.datetime), 'Missing or invalid profile date')
    return value.replace(tzinfo=dt.timezone.utc) if value.tzinfo is None else value.astimezone(dt.timezone.utc)


def iso(value):
    return utc(value).isoformat().replace('+00:00', 'Z')


def run_openssl(arguments, data=None):
    result = subprocess.run(['openssl', *arguments], input=data, capture_output=True)
    require(result.returncode == 0, 'OpenSSL validation failed during ' + arguments[0])
    return result.stdout


def digest_file(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def certificate_details(der, now):
    fingerprint = hashlib.sha256(der).hexdigest()
    dates = run_openssl(['x509', '-inform', 'DER', '-noout', '-startdate', '-enddate'], der).decode()
    values = {}
    for line in dates.splitlines():
        key, value = line.split('=', 1)
        values[key] = dt.datetime.strptime(value, '%b %d %H:%M:%S %Y %Z').replace(tzinfo=dt.timezone.utc)
    require(values['notBefore'] <= now < values['notAfter'], 'Signing certificate is not currently valid')
    subject = run_openssl(['x509', '-inform', 'DER', '-noout', '-subject', '-nameopt', 'RFC2253'], der).decode().strip()
    subject = re.sub(r'^subject\s*=\s*', '', subject)
    teams = re.findall(r'(?:^|,)OU=([A-Z0-9]{10})(?=,|$)', subject)
    require(len(teams) == 1, 'Signing certificate must identify one Apple team')
    require(re.search(r'(?:^|,)CN=(?:Apple|iPhone) Distribution(?:[^,]*)(?:,|$)', subject),
            'Signing certificate is not a distribution certificate')
    return {'sha256': fingerprint, 'team': teams[0], 'expiration': iso(values['notAfter'])}


def safe_archive(archive):
    names = archive.namelist()
    require(len(names) == len(set(names)), 'Duplicate ZIP paths')
    require(names, 'Empty ZIP archive')
    for item in archive.infolist():
        name = item.filename
        path = PurePosixPath(name)
        normalized = str(path) + ('/' if item.is_dir() else '')
        require(name and '\\' not in name and '\x00' not in name and ':' not in name
                and not path.is_absolute() and '..' not in path.parts and normalized == name,
                'Unsafe or noncanonical ZIP path')
        require(not stat.S_ISLNK(item.external_attr >> 16), 'Unsupported ZIP symlink')
        require(not item.flag_bits & 1, 'Unexpected encrypted ZIP member')
    require(archive.testzip() is None, 'ZIP CRC verification failed')
    return names


def macho_slices(data):
    magic = data[:4]
    if magic in MACH_MAGICS - {b'\xca\xfe\xba\xbe', b'\xbe\xba\xfe\xca',
                              b'\xca\xfe\xba\xbf', b'\xbf\xba\xfe\xca'}:
        return [data]
    require(magic in MACH_MAGICS and len(data) >= 8, 'Invalid Mach-O header')
    endian = '>' if magic[:1] == b'\xca' else '<'
    is_64 = magic in (b'\xca\xfe\xba\xbf', b'\xbf\xba\xfe\xca')
    count = struct.unpack_from(endian + 'I', data, 4)[0]
    entry_size = 32 if is_64 else 20
    table_end = 8 + count * entry_size
    require(0 < count <= 32 and table_end <= len(data), 'Invalid fat Mach-O table')
    slices, ranges = [], []
    for index in range(count):
        entry = 8 + index * entry_size
        offset, size = struct.unpack_from(endian + ('QQ' if is_64 else 'II'), data, entry + 8)
        require(size and offset >= table_end and offset + size <= len(data), 'Invalid fat Mach-O slice')
        require(all(offset + size <= start or end <= offset for start, end in ranges), 'Overlapping Mach-O slices')
        ranges.append((offset, offset + size))
        piece = data[offset:offset + size]
        require(piece[:4] in (b'\xce\xfa\xed\xfe', b'\xcf\xfa\xed\xfe',
                               b'\xfe\xed\xfa\xce', b'\xfe\xed\xfa\xcf'), 'Invalid nested Mach-O slice')
        slices.append(piece)
    return slices


def commands(data):
    magic = data[:4]
    endian = '<' if magic in (b'\xce\xfa\xed\xfe', b'\xcf\xfa\xed\xfe') else '>'
    header = 32 if magic in (b'\xcf\xfa\xed\xfe', b'\xfe\xed\xfa\xcf') else 28
    require(len(data) >= header, 'Truncated Mach-O header')
    cpu = struct.unpack_from(endian + 'I', data, 4)[0]
    count, size = struct.unpack_from(endian + 'II', data, 16)
    end = header + size
    require(count <= 65536 and end <= len(data), 'Invalid Mach-O load command table')
    result, offset = [], header
    for _ in range(count):
        require(offset + 8 <= end, 'Truncated Mach-O load command')
        command, length = struct.unpack_from(endian + 'II', data, offset)
        require(length >= 8 and length % 4 == 0 and offset + length <= end, 'Invalid Mach-O load command size')
        result.append((command, data[offset:offset + length]))
        offset += length
    require(offset == end, 'Mach-O command count and size differ')
    return endian, cpu, result


def cstring(blob, offset):
    require(0 < offset < len(blob), 'Invalid code signature string offset')
    end = blob.find(b'\x00', offset)
    require(end >= offset, 'Unterminated code signature string')
    return blob[offset:end].decode('utf-8')


def superblob(data):
    require(len(data) >= 12, 'Truncated Mach-O signature')
    magic, length, count = struct.unpack_from('>III', data)
    require(magic == 0xFADE0CC0 and 12 <= length <= len(data) and count <= 1024,
            'Invalid Mach-O embedded signature')
    table_end = 12 + count * 8
    require(table_end <= length, 'Truncated signature index')
    slots, spans = {}, []
    for index in range(count):
        slot, offset = struct.unpack_from('>II', data, 12 + index * 8)
        require(slot not in slots and table_end <= offset and offset + 8 <= length,
                'Invalid or duplicate signature slot')
        _, size = struct.unpack_from('>II', data, offset)
        require(size >= 8 and offset + size <= length, 'Invalid signature blob length')
        require(all(offset + size <= start or end <= offset for start, end in spans),
                'Overlapping signature blobs')
        slots[slot] = data[offset:offset + size]
        spans.append((offset, offset + size))
    require(0 in slots and 0x10000 in slots, 'Missing CodeDirectory or CMS signature')
    require(struct.unpack_from('>I', slots[0])[0] == 0xFADE0C02, 'Invalid primary CodeDirectory')
    require(struct.unpack_from('>I', slots[0x10000])[0] == 0xFADE0B01, 'Invalid CMS signature wrapper')
    return slots


def code_directory(blob, executable, signature_offset, slots, external_slots):
    require(len(blob) >= 44 and struct.unpack_from('>I', blob)[0] == 0xFADE0C02, 'Invalid CodeDirectory')
    _, length, version, _, hash_offset, ident_offset, special_count, count, limit = struct.unpack_from('>9I', blob)
    hash_size, hash_type, _, page_exp = struct.unpack_from('>4B', blob, 36)
    algorithms = {1: ('sha1', 20), 2: ('sha256', 32), 3: ('sha256', 20),
                  4: ('sha384', 48), 5: ('sha512', 64)}
    require(length == len(blob) and version >= 0x20001 and hash_type in algorithms,
            'Unsupported CodeDirectory')
    algorithm, expected_size = algorithms[hash_type]
    require(hash_size == expected_size and page_exp <= 30, 'Invalid CodeDirectory hash parameters')
    minimum_length = 44 if version < 0x20100 else 48
    if version >= 0x20200:
        minimum_length = 52
    if version >= 0x20300:
        minimum_length = 64
    if version >= 0x20400:
        minimum_length = 88
    if version >= 0x20500:
        minimum_length = 96
    if version >= 0x20600:
        minimum_length = 108
    require(len(blob) >= minimum_length, 'Truncated versioned CodeDirectory')
    if version >= 0x20100:
        require(struct.unpack_from('>I', blob, 44)[0] == 0, 'Scatter CodeDirectories are unsupported')
    if version >= 0x20300 and limit == 0xFFFFFFFF:
        limit = struct.unpack_from('>Q', blob, 56)[0]
    require(0 < limit <= signature_offset <= len(executable), 'Invalid signed-code limit')
    page_size = (1 << page_exp) if page_exp else limit
    require(count == (limit + page_size - 1) // page_size, 'Incorrect code-page count')
    require(hash_offset - special_count * hash_size >= minimum_length
            and hash_offset + count * hash_size <= len(blob), 'CodeDirectory hashes out of bounds')
    def hashed(value):
        return hashlib.new(algorithm, value).digest()[:hash_size]
    for index in range(count):
        start = index * page_size
        require(hashed(executable[start:min(start + page_size, limit)])
                == blob[hash_offset + index * hash_size:hash_offset + (index + 1) * hash_size],
                'Signed Mach-O code-page hash mismatch')
    for slot, value in {**slots, **external_slots}.items():
        if 0 < slot < 0x1000:
            require(slot <= special_count, 'Signature metadata is not bound by the CodeDirectory')
            require(hashed(value) == blob[hash_offset - slot * hash_size:hash_offset - (slot - 1) * hash_size],
                    'Signed Mach-O entitlement or resource hash mismatch')
    require(minimum_length <= ident_offset < hash_offset - special_count * hash_size,
            'CodeDirectory identifier overlaps hash data')
    identifier = cstring(blob, ident_offset)
    team_offset = struct.unpack_from('>I', blob, 48)[0] if version >= 0x20200 else 0
    if team_offset:
        require(minimum_length <= team_offset < hash_offset - special_count * hash_size,
                'CodeDirectory team overlaps hash data')
    team = cstring(blob, team_offset) if team_offset else None
    return identifier, team


def cms_signer(cms, directory, temporary):
    content = temporary / 'code-directory.bin'
    signer = temporary / 'cms-signer.pem'
    content.write_bytes(directory)
    # Validate the CMS signature; no Apple CA/chain trust assertion is made.
    run_openssl(['cms', '-verify', '-binary', '-inform', 'DER', '-noverify',
                 '-content', str(content), '-signer', str(signer)], cms)
    certificates = re.findall(br'-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----', signer.read_bytes(), re.S)
    require(len(certificates) == 1, 'Expected exactly one CMS signer')
    return ssl.PEM_cert_to_DER_cert(certificates[0].decode())


def verify_macho(data, temporary, certificate_cache, now, expected=None, external_slots=None):
    records = []
    for executable in macho_slices(data):
        endian, cpu, load_commands = commands(executable)
        signatures = [raw for command, raw in load_commands if command == 0x1D]
        require(len(signatures) == 1 and len(signatures[0]) == 16, 'Expected one LC_CODE_SIGNATURE per slice')
        offset, size = struct.unpack_from(endian + 'II', signatures[0], 8)
        require(size and offset + size <= len(executable), 'Mach-O signature out of bounds')
        for command, raw in load_commands:
            if command in (0x21, 0x2C):
                require(len(raw) >= 20 and struct.unpack_from(endian + 'I', raw, 16)[0] == 0,
                        'Unexpected encrypted Mach-O')
        slots = superblob(executable[offset:offset + size])
        cds = [blob for slot, blob in slots.items() if slot == 0 or 0x1000 <= slot <= 0x1005]
        identities = [code_directory(blob, executable, offset, slots, external_slots or {}) for blob in cds]
        require(len(set(identities)) == 1, 'CodeDirectories disagree on code identity')
        identifier, team = identities[0]
        der = cms_signer(slots[0x10000][8:], slots[0], temporary)
        fingerprint = hashlib.sha256(der).hexdigest()
        if fingerprint not in certificate_cache:
            certificate_cache[fingerprint] = certificate_details(der, now)
        require(team == certificate_cache[fingerprint]['team'], 'CodeDirectory team differs from signer certificate')
        xml = None
        if 5 in slots:
            require(struct.unpack_from('>I', slots[5])[0] == 0xFADE7171, 'Invalid XML entitlement blob')
            xml = plistlib.loads(slots[5][8:])
            require(isinstance(xml, dict), 'Entitlements are not a dictionary')
        if 7 in slots:
            require(struct.unpack_from('>I', slots[7])[0] == 0xFADE7172 and len(slots[7]) > 8,
                    'Invalid DER entitlement blob')
        if expected:
            require(cpu == 0x0100000C, 'Application executable is not ARM64')
            require(identifier == expected['identifier'], 'Signed code identity differs from bundle identity')
            require(xml == expected['entitlements'], 'Signed XML entitlements differ from concrete profile grants')
            require(7 in slots, 'Missing generated DER entitlements')
            require(fingerprint in expected['certificate_fingerprints'], 'Signer certificate is not granted by profile')
        records.append({'certificate_sha256': fingerprint, 'xml_entitlements': xml,
                        'der_entitlements_present': 7 in slots})
    require(len({record['certificate_sha256'] for record in records}) == 1,
            'Mach-O slices use different signing certificates')
    return records


def identifier_grant_matches(grant, identifier):
    """Recognize Apple exact IDs, '*' and a single final-segment wildcard."""
    if not isinstance(grant, str) or not isinstance(identifier, str):
        return False
    if '*' not in grant:
        return grant == identifier
    if grant == '*':
        return bool(identifier)
    return (grant.count('*') == 1 and grant.endswith('.*')
            and identifier.startswith(grant[:-1]) and len(identifier) > len(grant) - 1)


def concrete_entitlements(profile, identifier):
    require(identifier in EXPECTED_IDS, 'Entitlement target is outside the authorized bundle scope')
    entitlements = plistlib.loads(plistlib.dumps(profile['Entitlements']))
    application_grant = entitlements.get('application-identifier')
    require(isinstance(application_grant, str) and '.' in application_grant, 'Missing profile application identifier')
    prefix, bundle_grant = application_grant.split('.', 1)
    require(identifier_grant_matches(bundle_grant, identifier)
            and prefix in profile.get('ApplicationIdentifierPrefix', []),
            'Profile application identity mismatch')
    application_id = prefix + '.' + identifier
    entitlements['application-identifier'] = application_id
    team = entitlements.get('com.apple.developer.team-identifier')
    require(team in profile.get('TeamIdentifier', []) and entitlements.get('get-task-allow') is False,
            'Profile team or Ad Hoc entitlement mismatch')
    groups = entitlements.get('keychain-access-groups')
    if groups is not None:
        require(isinstance(groups, list) and groups, 'Invalid profile keychain grants')
        concrete = []
        for group in groups:
            # Independently claim only app-scoped rights, leaving this unused
            # literal system grant in the provisioning allowlist (TN3125).
            if group == 'com.apple.token':
                continue
            group = application_id if group == prefix + '.*' else group
            require(group in (application_id, prefix + '.' + ROOT_ID), 'Unexpected keychain entitlement scope')
            if group not in concrete:
                concrete.append(group)
        require(concrete, 'Profile has no scoped app keychain grant')
        entitlements['keychain-access-groups'] = concrete
    def wildcard(value):
        if isinstance(value, str):
            return '*' in value
        if isinstance(value, dict):
            return any(wildcard(item) for item in value.values())
        if isinstance(value, list):
            return any(wildcard(item) for item in value)
        return False
    require(not wildcard(entitlements), 'Wildcard entitlement remained in concrete grants')
    return entitlements


def verify(ipa, receipt_path):
    ipa, receipt_path = Path(ipa), Path(receipt_path)
    now = dt.datetime.now(dt.timezone.utc)
    receipt = json.loads(receipt_path.read_text())
    digest = digest_file(ipa)
    require(receipt.get('sha256') == digest, 'IPA SHA256 differs from CI receipt')
    require(receipt.get('file') == ipa.name, 'IPA filename differs from CI receipt')
    require(receipt.get('source_commit') == SOURCE_COMMIT
            and receipt.get('input_source_commit') == INPUT_SOURCE_COMMIT
            and receipt.get('input_sha256') == ORIGINAL_SHA,
            'CI receipt source/input differs from authorized pins')
    require(receipt.get('bundle_identifier') == ROOT_ID and receipt.get('distribution') == 'IOS_APP_ADHOC'
            and receipt.get('registered_device_count') == 1 and receipt.get('provisioned_bundle_count') == 5,
            'CI receipt signing scope mismatch')
    ci_signature = receipt.get('signature_verification', '')
    require(isinstance(ci_signature, str) and 'codesign deep strict passed' in ci_signature,
            'Missing macOS codesign verification evidence')
    require(receipt.get('device_installation') == 'not tested' and receipt.get('posting') == 'not tested',
            'CI receipt contains an unexpected device-test claim')
    certificate_cache, profiles, verified_executables, provisioned_devices = {}, [], set(), set()
    total_macho = total_slices = 0
    with tempfile.TemporaryDirectory(prefix='bereal-delivery-check-') as directory, zipfile.ZipFile(ipa) as archive:
        temporary = Path(directory)
        names = safe_archive(archive)
        root_infos = [name for name in names if name.startswith('Payload/') and name.count('/') == 2
                      and name.endswith('.app/Info.plist')]
        require(root_infos == ['Payload/BeReal.app/Info.plist'], 'Expected the single BeReal root application')
        app = 'Payload/BeReal.app'
        outside_files = [name for name in names if name not in ('Payload/', app + '/')
                         and not name.startswith(app + '/')]
        require(all(name in INHERITED_OUTSIDE_FILES for name in outside_files),
                'Unexpected files outside the root application')
        inherited_files = []
        for name in outside_files:
            size, expected_digest = INHERITED_OUTSIDE_FILES[name]
            item = archive.getinfo(name)
            require(not item.is_dir() and item.file_size == size, 'Inherited outside-app marker length mismatch')
            data = archive.read(item)
            require(len(data) == size, 'Inherited outside-app marker length mismatch')
            marker_digest = hashlib.sha256(data).hexdigest()
            require(marker_digest == expected_digest, 'Inherited outside-app marker SHA256 mismatch')
            inherited_files.append({'path': name, 'bytes': size, 'sha256': marker_digest})
        bundle_infos = [root_infos[0]] + sorted(name for name in names if name.startswith(app + '/PlugIns/')
                                               and name.count('/') == 4 and name.endswith('.appex/Info.plist'))
        nested_infos = [name for name in names if name.endswith(('.appex/Info.plist', '.app/Info.plist'))]
        require(len(bundle_infos) == 5 and set(bundle_infos) == set(nested_infos), 'Expected root app and exactly four extensions')
        seen_ids = set()
        all_signers = set()
        for info_path in bundle_infos:
            bundle = info_path.rsplit('/', 1)[0]
            info = plistlib.loads(archive.read(info_path))
            identifier = info.get('CFBundleIdentifier')
            require(identifier in EXPECTED_IDS and identifier not in seen_ids, 'Unexpected or duplicate bundle identity')
            seen_ids.add(identifier)
            if identifier == ROOT_ID:
                require(info.get('CFBundleShortVersionString') == '4.93.0' and info.get('CFBundleVersion') == '23026',
                        'BeReal root version/build mismatch')
            executable = info.get('CFBundleExecutable')
            require(isinstance(executable, str) and executable and '/' not in executable and '\\' not in executable
                    and executable not in ('.', '..'), 'Invalid executable name')
            executable_path = bundle + '/' + executable
            resource_path = bundle + '/_CodeSignature/CodeResources'
            require(resource_path in names and executable_path in names, 'Missing executable or bundle resource seal')
            profile_raw = archive.read(bundle + '/embedded.mobileprovision')
            profile = plistlib.loads(run_openssl(['cms', '-verify', '-binary', '-inform', 'DER', '-noverify'], profile_raw))
            require(isinstance(profile, dict), 'Provisioning profile is not a dictionary')
            require(utc(profile.get('CreationDate')) <= now < utc(profile.get('ExpirationDate')),
                    'Provisioning profile is not currently valid')
            profile_uuid = str(uuid.UUID(profile.get('UUID', '')))
            require(not profile.get('ProvisionsAllDevices'), 'Unexpected enterprise profile')
            devices = profile.get('ProvisionedDevices')
            require(isinstance(devices, list) and len(devices) == 1 and isinstance(devices[0], str) and devices[0],
                    'Profile must target exactly one device')
            provisioned_devices.add(devices[0])
            certs = profile.get('DeveloperCertificates')
            require(isinstance(certs, list) and certs and all(isinstance(cert, bytes) for cert in certs),
                    'Missing provisioning certificate grants')
            grants = {hashlib.sha256(cert).hexdigest() for cert in certs}
            entitlements = concrete_entitlements(profile, identifier)
            records = verify_macho(archive.read(executable_path), temporary, certificate_cache, now,
                                  expected={'identifier': identifier, 'entitlements': entitlements,
                                            'certificate_fingerprints': grants},
                                  external_slots={1: archive.read(info_path), 3: archive.read(resource_path)})
            signer = records[0]['certificate_sha256']
            require(entitlements['com.apple.developer.team-identifier'] == certificate_cache[signer]['team'],
                    'Profile team differs from signer certificate')
            all_signers.add(signer)
            total_macho += 1
            total_slices += len(records)
            verified_executables.add(executable_path)
            profiles.append({'bundle_identifier': identifier, 'profile_uuid': profile_uuid,
                             'application_identifier_kind': ('wildcard' if '*' in profile['Entitlements']['application-identifier']
                                                             else 'explicit'),
                             'expiration_date': iso(profile['ExpirationDate']), 'provisioned_device_count': 1,
                             'certificate_sha256': signer, 'entitlement_keys': sorted(entitlements),
                             'xml_entitlements_match_concrete_profile': True, 'der_entitlements_present': True})
        require(seen_ids == EXPECTED_IDS and len(provisioned_devices) == 1,
                'Bundles or provisioned device differ across profiles')
        distinct_profile_count = len({profile['profile_uuid'] for profile in profiles})
        wildcard_profiles = [profile for profile in profiles if profile['application_identifier_kind'] == 'wildcard']
        profile_selection = receipt.get('profile_selection')
        if wildcard_profiles:
            require(profile_selection == 'existing_wildcard_read_only' and len(wildcard_profiles) == 5
                    and distinct_profile_count == 1, 'Wildcard profile selection differs from CI evidence')
        else:
            require(profile_selection != 'existing_wildcard_read_only', 'CI claimed wildcard selection for explicit profiles')
        if 'distinct_profile_count' in receipt:
            require(receipt['distinct_profile_count'] == distinct_profile_count, 'CI distinct profile count mismatch')
        for item in archive.infolist():
            if item.is_dir() or item.filename in verified_executables or item.file_size < 4:
                continue
            with archive.open(item) as stream:
                magic = stream.read(4)
            if magic in MACH_MAGICS:
                records = verify_macho(archive.read(item), temporary, certificate_cache, now)
                all_signers.update(record['certificate_sha256'] for record in records)
                total_macho += 1
                total_slices += len(records)
        require(len(all_signers) == 1, 'Nested code uses a different signing certificate')
        certificate_sha = next(iter(all_signers))
        if 'certificate_sha256' in receipt:
            require(receipt['certificate_sha256'] == certificate_sha, 'Signing certificate differs from CI receipt')
        if 'profiles' in receipt:
            ci_profiles = receipt['profiles']
            require(isinstance(ci_profiles, list) and len(ci_profiles) == 5, 'CI profile receipt has incorrect bundle count')
            by_id = {profile['bundle_identifier']: profile for profile in ci_profiles}
            require(set(by_id) == EXPECTED_IDS, 'CI profile receipt has incorrect identities')
            for profile in profiles:
                recorded = by_id[profile['bundle_identifier']]
                require(str(uuid.UUID(recorded['profile_uuid'])) == profile['profile_uuid'], 'CI profile UUID mismatch')
                if 'expiration_date' in recorded:
                    recorded_date = dt.datetime.fromisoformat(recorded['expiration_date'].replace('Z', '+00:00'))
                    require(iso(recorded_date) == profile['expiration_date'], 'CI profile expiration mismatch')
                if 'entitlement_keys' in recorded:
                    require(sorted(recorded['entitlement_keys']) == profile['entitlement_keys'], 'CI profile entitlement keys mismatch')
                if 'certificate_sha256' in recorded:
                    require(recorded['certificate_sha256'] == profile['certificate_sha256'], 'CI profile signer certificate mismatch')
                if 'provisioned_device_count' in recorded:
                    require(recorded['provisioned_device_count'] == 1, 'CI profile device count mismatch')
        adapter_path = app + '/Frameworks/CameraRollAdapter.dylib'
        require(adapter_path in names, 'Missing compiled photo adapter')
        root_info = plistlib.loads(archive.read(root_infos[0]))
        root_data = archive.read(app + '/' + root_info['CFBundleExecutable'])
        for piece in macho_slices(root_data):
            endian, _, load_commands = commands(piece)
            dependencies = []
            for command, raw in load_commands:
                if command == 0xC:
                    require(len(raw) >= 24, 'Invalid dylib load command')
                    dependencies.append(cstring(raw, struct.unpack_from(endian + 'I', raw, 8)[0]))
            require(dependencies.count(ADAPTER) == 1, 'Photo adapter dependency is not injected exactly once')
        require(archive.read(adapter_path)[:4] in MACH_MAGICS, 'Photo adapter is not Mach-O code')
    return {'file': ipa.name, 'sha256': digest, 'validated_at': iso(now),
            'ci_receipt_sha256': digest_file(receipt_path), 'source_commit': SOURCE_COMMIT,
            'input_source_commit': INPUT_SOURCE_COMMIT,
            'input_sha256': ORIGINAL_SHA,
            'independently_verified': {'zip_crc_and_safe_unique_paths': True, 'ipa_hash_matches_ci_receipt': True,
                                      'inherited_outside_app_files_verified': inherited_files,
                                      'bundle_count': 5, 'same_single_provisioned_device': True,
                                      'distinct_profile_count': distinct_profile_count,
                                      'distribution_profile_entitlements': 'Ad Hoc; get-task-allow false',
                                      'certificate_sha256': certificate_sha,
                                      'certificate_expiration_date': certificate_cache[certificate_sha]['expiration'],
                                      'signed_macho_file_count': total_macho, 'signed_macho_slice_count': total_slices,
                                      'cms_signature_and_code_page_hashes': True,
                                      'xml_entitlement_and_resource_special_slot_hashes': True,
                                      'adapter_dependency_injected_once': True, 'profiles': profiles},
            'ci_evidence': {'macos_codesign_verification': ci_signature, 'registered_device_count': 1,
                            'profile_selection': profile_selection or 'exact profiles'},
            'limitations': ['Apple certificate-chain trust and codesign are not independently checked on Linux.',
                            'Bundle resource manifests are hash-checked; their individual file seals rely on CI codesign.',
                            'DER entitlement blobs are present and hash-checked; XML entitlements are parsed and compared.',
                            'Device installation, launch, draft, posting, notifications and widgets were not tested.']}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('ipa', type=Path)
    parser.add_argument('receipt', type=Path)
    parser.add_argument('--output', '-o', type=Path, help='Write the safe validation JSON to this path')
    options = parser.parse_args()
    try:
        result = verify(options.ipa, options.receipt)
    except Exception as error:
        # Library/OpenSSL diagnostics may include profile or certificate details.
        parser.exit(1, 'ERROR: ' + (str(error) if isinstance(error, ValueError) else type(error).__name__) + '\n')
    text = json.dumps(result, indent=2) + '\n'
    if options.output:
        require(options.output.resolve() not in (options.ipa.resolve(), options.receipt.resolve()),
                'Validation output must not replace delivery input')
        options.output.parent.mkdir(parents=True, exist_ok=True)
        options.output.write_text(text)
    print(text, end='')


if __name__ == '__main__':
    main()
