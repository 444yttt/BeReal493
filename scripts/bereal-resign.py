#!/usr/bin/env python3
"""Scoped Ad Hoc signing inside Y3POSClient. Private assets never leave the runner."""
import argparse
import base64
import datetime
import hashlib
import hmac
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import plistlib
import re
import secrets
import shutil
import ssl
import stat
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
import zipfile

ORIGINAL_SHA = 'e7d77665740c61f2b0d6eae21cb6052acd2add364db3f6b5fc9ef9198ac31cbc'
SOURCE_COMMIT = '1f749cd1b2433d2a32694d5c91849d22f84f429f'
ROOT_ID = 'com.ayato.bereal493'
PREFIX = 'AlexisBarreyat.BeReal'
SAFE_SUFFIXES = ('', '.iMessageExtension', '.RealMojiNotificationContentExtension', '.NotificationServiceExtension', '.Widgets')
# Exact direct-download hosts; the encrypted URL may narrow this set further.
URL_INPUT_ALLOWED_HOSTS = ('cvws.icloud-content.com', '*.icloud-content.com')
URL_INPUT_HMAC_DOMAIN = b'BeReal493EncryptedURLInputV2'

helper = None


def configure_openssl():
    # Apple's /usr/bin/openssl is LibreSSL on some runners. OpenSSL 3 supports
    # both OAEP SHA256 and authenticated CMS delivery; Homebrew is preinstalled.
    candidates = [os.environ.get('BEREAL_OPENSSL', ''),
                  '/opt/homebrew/opt/openssl@3/bin/openssl',
                  '/usr/local/opt/openssl@3/bin/openssl', shutil.which('openssl')]
    for candidate in candidates:
        if not candidate or not Path(candidate).is_file(): continue
        probe = subprocess.run([candidate, 'version'], capture_output=True)
        if probe.returncode == 0 and probe.stdout.startswith(b'OpenSSL 3.'):
            os.environ['PATH'] = str(Path(candidate).parent) + os.pathsep + os.environ.get('PATH', '')
            return
    raise RuntimeError('OpenSSL 3 is required; configure the runner with Homebrew openssl@3')


def load_helper():
    spec = importlib.util.spec_from_file_location('existing_helper', Path(__file__).with_name('prepare-ci-profile.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def run(args, data=None):
    result = subprocess.run(args, input=data, capture_output=True)
    if result.returncode:
        # Only command names/subcommands are diagnostics. Arguments may contain
        # temporary passwords, and stderr from signing tools is never published.
        tool = Path(args[0]).name
        operation = args[1] if tool in ('openssl', 'security') and len(args) > 1 else ''
        raise RuntimeError('A signing/tool command failed: ' + tool + ' ' + operation + ' (exit ' + str(result.returncode) + ')')
    return result.stdout


def private(path, data):
    path.write_bytes(data); path.chmod(0o600); return path


def sha256_file(path):
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1048576), b''): digest.update(chunk)
    return digest.hexdigest()


def read_pkcs12(p12, options, password_env='P12_PASSWORD'):
    arguments = ['openssl', 'pkcs12', '-in', str(p12), '-passin', 'env:' + password_env] + options
    try:
        return run(arguments)
    except RuntimeError:
        # Existing CI identities may use RC2/PBES1; OpenSSL 3 disables those
        # algorithms by default. This fallback is also used by readiness CI.
        return run(arguments + ['-legacy'])


def download(url, path):
    if not url.startswith('https://'):
        raise RuntimeError('HTTPS input is required')
    with urllib.request.urlopen(url, timeout=120) as response, path.open('wb') as target:
        while chunk := response.read(1048576): target.write(chunk)


def validate_url_input(url, allowed_hosts):
    def permitted_scope(host):
        return isinstance(host, str) and (host in URL_INPUT_ALLOWED_HOSTS or re.fullmatch(r'[a-z0-9.-]+\.icloud-content\.com', host))
    if not isinstance(allowed_hosts, list) or not allowed_hosts or any(not permitted_scope(host) for host in allowed_hosts):
        raise RuntimeError('Unapproved encrypted URL input host scope')
    if not isinstance(url, str) or len(url) > 16384 or any(ord(char) < 32 for char in url):
        raise RuntimeError('Invalid encrypted URL input')
    try:
        parsed = urllib.parse.urlsplit(url)
        hostname = parsed.hostname or ''
        allowed = hostname in allowed_hosts or ('*.icloud-content.com' in allowed_hosts and bool(re.fullmatch(r'[a-z0-9.-]+\.icloud-content\.com', hostname)))
        valid = parsed.scheme == 'https' and allowed and parsed.port in (None, 443) and parsed.username is None and parsed.password is None and not parsed.fragment
    except ValueError:
        valid = False
    if not valid: raise RuntimeError('Encrypted URL input requires an authorized HTTPS host')


class ScopedInputRedirects(urllib.request.HTTPRedirectHandler):
    def __init__(self, allowed_hosts):
        self.allowed_hosts = allowed_hosts

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        validate_url_input(newurl, self.allowed_hosts)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def download_url_input(url, path, allowed_hosts):
    validate_url_input(url, allowed_hosts)
    opener = urllib.request.build_opener(ScopedInputRedirects(allowed_hosts))
    try:
        with opener.open(url, timeout=120) as response, path.open('wb') as target:
            validate_url_input(response.geturl(), allowed_hosts)
            while chunk := response.read(1048576): target.write(chunk)
    except urllib.error.HTTPError as error:
        # The signed URL is a temporary access credential: never emit the URL,
        # HTTP error text, body or request/response headers in CI diagnostics.
        raise RuntimeError('Encrypted URL input download failed (HTTP ' + str(error.code) + ')') from None
    except (urllib.error.URLError, TimeoutError, OSError):
        raise RuntimeError('Encrypted URL input download could not complete') from None


def extract(source, root):
    with zipfile.ZipFile(source) as archive:
        names = archive.namelist()
        if len(names) != len(set(names)): raise RuntimeError('Duplicate archive paths')
        for item in archive.infolist():
            name = PurePosixPath(item.filename)
            if name.is_absolute() or '..' in name.parts or stat.S_ISLNK(item.external_attr >> 16):
                raise RuntimeError('Unsupported archive path')
        archive.extractall(root)
        for item in archive.infolist():
            path = root / item.filename
            mode = (item.external_attr >> 16) & 0o777
            if mode and path.exists(): path.chmod(mode)


def decode_identity(root, need_private_key=True, certificate_env='BUILD_CERTIFICATE_BASE64', password_env='P12_PASSWORD'):
    required = [certificate_env, password_env, 'APPLE_TEAM_ID', 'ASC_KEY_ID', 'ASC_ISSUER_ID', 'ASC_PRIVATE_KEY']
    if any(not os.environ.get(name) for name in required): raise RuntimeError('Required existing signing assets are missing')
    p12 = private(root / 'identity.p12', base64.b64decode(''.join(os.environ[certificate_env].split()), validate=True))
    pem = read_pkcs12(p12, ['-clcerts', '-nokeys'], password_env)
    certificates = re.findall(br'-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----', pem, re.S)
    if len(certificates) != 1: raise RuntimeError('Expected one certificate')
    der = ssl.PEM_cert_to_DER_cert(certificates[0].decode())
    key = None
    if need_private_key:
        key = private(root / 'signing-private.pem', read_pkcs12(p12, ['-nocerts', '-nodes'], password_env))
        public_from_key = run(['openssl', 'pkey', '-in', str(key), '-pubout', '-outform', 'DER'])
        public_from_cert = run(['openssl', 'x509', '-inform', 'DER', '-pubkey', '-noout'], der)
        public_from_cert = run(['openssl', 'pkey', '-pubin', '-outform', 'DER'], public_from_cert)
        if public_from_key != public_from_cert: raise RuntimeError('Certificate/private-key mismatch')
    run(['openssl', 'x509', '-inform', 'DER', '-noout', '-checkend', '0'], der)
    team = os.environ['APPLE_TEAM_ID']
    if not re.fullmatch('[A-Z0-9]{10}', team): raise RuntimeError('Invalid configured Apple team')
    subject = run(['openssl', 'x509', '-inform', 'DER', '-noout', '-subject', '-nameopt', 'RFC2253'], der).decode()
    if team not in re.findall(r'(?:^|,)OU=([A-Z0-9]{10})(?=,|$)', re.sub(r'^subject\s*=\s*', '', subject.strip())):
        raise RuntimeError('Existing certificate belongs to another Apple team')
    asc = private(root / 'AuthKey.p8', (os.environ['ASC_PRIVATE_KEY'].replace('\\n', '\n').strip() + '\n').encode())
    return p12, der, key, asc


class RefreshingAppleAPI:
    """Keep the existing helper's guarded API while renewing its ten-minute JWT."""
    def __init__(self, asc):
        self.asc = asc
        self.api = None
        self.expires = 0

    def current(self):
        if self.api is None or time.monotonic() >= self.expires:
            token = helper.make_jwt(os.environ['ASC_KEY_ID'], os.environ['ASC_ISSUER_ID'], self.asc)
            self.api = helper.AppleAPI(token)
            self.expires = time.monotonic() + 420
        return self.api

    def collection(self, *args, **kwargs): return self.current().collection(*args, **kwargs)
    def request(self, *args, **kwargs): return self.current().request(*args, **kwargs)


def signing_readiness(api, der):
    matches = [c for c in api.collection('/v1/certificates') if c.get('attributes', {}).get('certificateContent') and hashlib.sha256(helper.decode_base64(c['attributes']['certificateContent'])).digest() == hashlib.sha256(der).digest()]
    if len(matches) != 1 or matches[0]['attributes'].get('certificateType') not in ('IOS_DISTRIBUTION', 'DISTRIBUTION') or not helper.is_future(matches[0]['attributes'].get('expirationDate')):
        raise RuntimeError('Existing Apple distribution certificate is not valid')
    devices = api.collection('/v1/devices', {'filter[platform]': 'IOS', 'filter[status]': 'ENABLED'})
    if len(devices) != 1 or devices[0].get('attributes', {}).get('status') != 'ENABLED' or devices[0].get('attributes', {}).get('platform') != 'IOS':
        raise RuntimeError('Expected exactly the one registered enabled iOS device')
    if not devices[0]['attributes'].get('udid'): raise RuntimeError('Registered device identifier is missing')
    return matches[0], devices[0]


def unwrap_input_keys(root, key, envelope):
    wrapped = private(root / 'wrapped-keys.bin', base64.b64decode(envelope['wrapped_keys'], validate=True))
    if not 128 <= wrapped.stat().st_size <= 1024: raise RuntimeError('Invalid wrapped transfer key')
    keys = run(['openssl', 'pkeyutl', '-decrypt', '-inkey', str(key), '-in', str(wrapped), '-pkeyopt', 'rsa_padding_mode:oaep', '-pkeyopt', 'rsa_oaep_md:sha256', '-pkeyopt', 'rsa_mgf1_md:sha256'])
    if len(keys) != 64: raise RuntimeError('Invalid decrypted transfer key')
    iv = base64.b64decode(envelope['iv'], validate=True)
    if len(iv) != 16: raise RuntimeError('Invalid IV')
    return keys, iv


def decrypt_url_input(root, key, envelope):
    if envelope.get('mode') != 'encrypted-https-url': raise RuntimeError('Unexpected encrypted URL input mode')
    keys, iv = unwrap_input_keys(root, key, envelope)
    ciphertext = base64.b64decode(envelope['encrypted_url'], validate=True)
    if not ciphertext or len(ciphertext) > 65536 or len(ciphertext) % 16: raise RuntimeError('Invalid encrypted URL payload')
    tag = hmac.new(keys[32:], URL_INPUT_HMAC_DOMAIN + iv + ciphertext, hashlib.sha256).digest()
    if not hmac.compare_digest(tag, base64.b64decode(envelope['hmac'], validate=True)):
        raise RuntimeError('Encrypted URL input authentication failed')
    plaintext = run(['openssl', 'enc', '-d', '-aes-256-cbc', '-K', keys[:32].hex(), '-iv', iv.hex()], ciphertext)
    payload = json.loads(plaintext)
    url, allowed_hosts = payload['url'], payload['allowed_hosts']
    validate_url_input(url, allowed_hosts)
    original = root / 'original.ipa'
    download_url_input(url, original, allowed_hosts)
    if sha256_file(original) != ORIGINAL_SHA: raise RuntimeError('Original IPA hash mismatch')
    print('Encrypted access URL restored; original IPA downloaded and its exact hash verified.')
    return original


def decrypt_input(root, key, envelope):
    if envelope.get('input_sha256') != ORIGINAL_SHA or envelope.get('source_commit') != SOURCE_COMMIT:
        raise RuntimeError('Unexpected encrypted input contract')
    if envelope.get('version') == 2: return decrypt_url_input(root, key, envelope)
    if envelope.get('version') == 3: return decrypt_local_input(root, key, envelope)
    if envelope.get('version') != 1: raise RuntimeError('Unexpected encrypted input version')
    commit = envelope.get('transfer_commit', '')
    if not re.fullmatch('[0-9a-f]{40}', commit): raise RuntimeError('Pinned transfer commit is required')
    keys, iv = unwrap_input_keys(root, key, envelope)
    authenticator = hmac.new(keys[32:], b'BeReal493EncryptedInputV1' + iv, hashlib.sha256)
    encrypted = root / 'input-encrypted.bin'
    with encrypted.open('wb') as output:
        for index, part in enumerate(envelope['parts']):
            expected = f'chunk-{index:03d}.bin'
            if part['path'] != expected or not re.fullmatch('[0-9a-f]{64}', part['sha256']): raise RuntimeError('Unexpected transfer part')
            piece = root / 'part.bin'
            download(f'https://raw.githubusercontent.com/444yttt/BeReal493/{commit}/ci-input/{expected}', piece)
            content = piece.read_bytes()
            if len(content) != part['bytes'] or hashlib.sha256(content).hexdigest() != part['sha256']:
                raise RuntimeError('Encrypted transfer part failed verification')
            output.write(content); authenticator.update(content)
    if not hmac.compare_digest(authenticator.digest(), base64.b64decode(envelope['hmac'], validate=True)):
        raise RuntimeError('Encrypted transfer authentication failed')
    original = root / 'original.ipa'
    run(['openssl', 'enc', '-d', '-aes-256-cbc', '-K', keys[:32].hex(), '-iv', iv.hex(), '-in', str(encrypted), '-out', str(original)])
    if sha256_file(original) != ORIGINAL_SHA: raise RuntimeError('Original IPA hash mismatch')
    print('Encrypted original IPA restored and its exact hash verified.')
    return original


def decrypt_local_input(root, key, envelope):
    if envelope.get('mode') != 'encrypted-local-file' or envelope.get('encrypted_file') != 'input-encrypted.bin':
        raise RuntimeError('Unexpected persistent encrypted input contract')
    encrypted = restore_artifact_input(root, envelope) if envelope.get('github_artifact') else Path('bereal-input-transfer') / 'input-encrypted.bin'
    if encrypted.is_symlink() or not encrypted.is_file() or encrypted.stat().st_size != envelope.get('encrypted_bytes') or sha256_file(encrypted) != envelope.get('encrypted_sha256'):
        raise RuntimeError('Persistent encrypted input is missing or failed verification')
    keys, iv = unwrap_input_keys(root, key, envelope)
    authenticator = hmac.new(keys[32:], b'BeReal493EncryptedInputV1' + iv, hashlib.sha256)
    with encrypted.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1048576), b''): authenticator.update(chunk)
    if not hmac.compare_digest(authenticator.digest(), base64.b64decode(envelope['hmac'], validate=True)):
        raise RuntimeError('Persistent encrypted input authentication failed')
    original = root / 'original.ipa'
    run(['openssl', 'enc', '-d', '-aes-256-cbc', '-K', keys[:32].hex(), '-iv', iv.hex(), '-in', str(encrypted), '-out', str(original)])
    if sha256_file(original) != ORIGINAL_SHA: raise RuntimeError('Original IPA hash mismatch')
    print('Persistent encrypted original IPA restored and its exact hash verified.')
    return original


class ArtifactAPINoRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl): return None


def validate_artifact_url(url):
    if not isinstance(url, str) or len(url) > 16384 or any(ord(char) < 32 for char in url):
        raise RuntimeError('Invalid encrypted artifact download URL')
    try:
        parsed = urllib.parse.urlsplit(url)
        host = parsed.hostname or ''
        trusted = bool(re.fullmatch(r'[a-z0-9.-]+\.(?:blob\.core\.windows\.net|githubusercontent\.com)', host))
        valid = parsed.scheme == 'https' and trusted and parsed.port in (None, 443) and parsed.username is None and parsed.password is None and not parsed.fragment
    except (ValueError, TypeError): valid = False
    if not valid: raise RuntimeError('Unapproved encrypted artifact download host')


class ScopedArtifactRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        validate_artifact_url(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def stream_artifact(response, path):
    count = 0
    with path.open('wb') as target:
        while chunk := response.read(1048576):
            count += len(chunk)
            if count > 1024 * 1024 * 1024: raise RuntimeError('Encrypted artifact exceeds the allowed size')
            target.write(chunk)


def fetch_artifact_archive(artifact_id, path):
    token = os.environ.get('GH_TOKEN', '')
    if not token: raise RuntimeError('The scoped CI GitHub token is required to retrieve encrypted input')
    api_url = 'https://api.github.com/repos/444yttt/Y3POSClient/actions/artifacts/' + str(artifact_id) + '/zip'
    request = urllib.request.Request(api_url, headers={'Authorization': 'Bearer ' + token,
        'Accept': 'application/vnd.github+json', 'X-GitHub-Api-Version': '2022-11-28'})
    # Never carry API Authorization through GitHub's signed-URL redirect.
    location = None
    try:
        with urllib.request.build_opener(ArtifactAPINoRedirects()).open(request, timeout=60) as response:
            stream_artifact(response, path)
            return
    except urllib.error.HTTPError as error:
        if error.code in (302, 303, 307, 308): location = error.headers.get('Location')
        else: raise RuntimeError('Encrypted artifact API request failed (HTTP ' + str(error.code) + ')') from None
        error.close()
    except (urllib.error.URLError, TimeoutError, OSError):
        raise RuntimeError('Encrypted artifact API request could not complete') from None
    validate_artifact_url(location)
    try:
        # New request and opener: no GitHub credential or original headers.
        with urllib.request.build_opener(ScopedArtifactRedirects()).open(urllib.request.Request(location), timeout=120) as response:
            validate_artifact_url(response.geturl())
            stream_artifact(response, path)
    except urllib.error.HTTPError as error:
        raise RuntimeError('Encrypted artifact download failed (HTTP ' + str(error.code) + ')') from None
    except (urllib.error.URLError, TimeoutError, OSError):
        raise RuntimeError('Encrypted artifact download could not complete') from None


def restore_artifact_input(root, envelope):
    artifact = envelope['github_artifact']
    if not isinstance(artifact, dict) or artifact.get('repository') != '444yttt/Y3POSClient':
        raise RuntimeError('Unapproved encrypted artifact repository')
    artifact_id = artifact.get('artifact_id')
    if not isinstance(artifact_id, int) or isinstance(artifact_id, bool) or not 0 < artifact_id < 10 ** 20:
        raise RuntimeError('A pinned encrypted artifact ID is required')
    digest = artifact.get('archive_sha256', '')
    if not isinstance(digest, str) or not re.fullmatch('[0-9a-f]{64}', digest):
        raise RuntimeError('A pinned encrypted artifact archive hash is required')
    archive = root / 'encrypted-input-artifact.zip'
    fetch_artifact_archive(artifact_id, archive)
    if sha256_file(archive) != digest: raise RuntimeError('Encrypted artifact archive hash mismatch')
    with zipfile.ZipFile(archive) as source:
        files = {item.filename for item in source.infolist() if not item.is_dir()}
        if files != {'input-encrypted.bin', 'input-metadata.json'}:
            raise RuntimeError('Encrypted artifact contains unexpected files')
    destination = root / 'artifact-input'
    extract(archive, destination)
    metadata = json.loads((destination / 'input-metadata.json').read_text())
    if metadata != {key: value for key, value in envelope.items() if key != 'github_artifact'}:
        raise RuntimeError('Encrypted artifact metadata differs from the pinned input envelope')
    return destination / 'input-encrypted.bin'


def encrypt_persistent_input(root, original, der):
    output = Path('bereal-input-transfer'); output.mkdir(exist_ok=True)
    encrypted = output / 'input-encrypted.bin'
    keys, iv = secrets.token_bytes(64), secrets.token_bytes(16)
    public_key = private(root / 'input-recipient-public.pem', run(['openssl', 'x509', '-inform', 'DER', '-pubkey', '-noout'], der))
    wrapped = run(['openssl', 'pkeyutl', '-encrypt', '-pubin', '-inkey', str(public_key), '-pkeyopt', 'rsa_padding_mode:oaep', '-pkeyopt', 'rsa_oaep_md:sha256', '-pkeyopt', 'rsa_mgf1_md:sha256'], keys)
    run(['openssl', 'enc', '-aes-256-cbc', '-K', keys[:32].hex(), '-iv', iv.hex(), '-in', str(original), '-out', str(encrypted)])
    authenticator = hmac.new(keys[32:], b'BeReal493EncryptedInputV1' + iv, hashlib.sha256)
    with encrypted.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1048576), b''): authenticator.update(chunk)
    encode = lambda value: base64.b64encode(value).decode('ascii')
    metadata = {'version': 3, 'mode': 'encrypted-local-file', 'input_sha256': ORIGINAL_SHA,
                'source_commit': SOURCE_COMMIT, 'encrypted_file': encrypted.name,
                'encrypted_bytes': encrypted.stat().st_size, 'encrypted_sha256': sha256_file(encrypted),
                'certificate_sha256': hashlib.sha256(der).hexdigest(),
                'wrapped_keys': encode(wrapped), 'iv': encode(iv), 'hmac': encode(authenticator.digest())}
    (output / 'input-metadata.json').write_text(json.dumps(metadata, indent=2) + '\n')
    print('Exact original input encrypted with a fresh envelope for persistent CI transfer.')
    return metadata


def validate_profile(resource, der, team, identifier, udid):
    attributes = resource.get('attributes', {})
    if attributes.get('profileType') != 'IOS_APP_ADHOC' or attributes.get('profileState') != 'ACTIVE':
        raise RuntimeError('Incorrect profile distribution type or state')
    raw = helper.decode_base64(attributes.get('profileContent', ''))
    if not raw or len(raw) > 10 * 1024 * 1024: raise RuntimeError('Invalid profile content')
    decoded = plistlib.loads(run(['openssl', 'cms', '-verify', '-inform', 'DER', '-noverify'], raw))
    entitlements = decoded.get('Entitlements', {})
    application_id = entitlements.get('application-identifier', '')
    if not isinstance(application_id, str) or '.' not in application_id: raise RuntimeError('Profile identity is missing')
    prefix, allowed = application_id.split('.', 1)
    if allowed != identifier or team not in decoded.get('TeamIdentifier', []): raise RuntimeError('Profile identity mismatch')
    if prefix not in decoded.get('ApplicationIdentifierPrefix', []): raise RuntimeError('Profile prefix mismatch')
    if entitlements.get('com.apple.developer.team-identifier') != team or entitlements.get('get-task-allow') is not False: raise RuntimeError('Profile entitlement mismatch')
    if der not in decoded.get('DeveloperCertificates', []) or not helper.is_future(decoded.get('ExpirationDate')) or not helper.is_future(attributes.get('expirationDate')):
        raise RuntimeError('Profile certificate/expiry mismatch')
    if decoded.get('ProvisionedDevices') != [udid] or decoded.get('ProvisionsAllDevices'): raise RuntimeError('Profile does not target only the registered device')
    try: profile_uuid = str(uuid.UUID(decoded.get('UUID', '')))
    except (ValueError, AttributeError, TypeError): raise RuntimeError('Invalid profile UUID') from None
    if attributes.get('uuid', '').lower() != profile_uuid: raise RuntimeError('Profile UUID differs from Apple metadata')
    concrete_entitlements(decoded, identifier)
    return raw, decoded


def concrete_entitlements(profile, identifier):
    """Turn the profile's keychain grant into an entitlement for this exact app.

    Profiles describe allowed permissions, not always the final entitlement
    value. In particular a keychain grant TEAM.* must never be signed verbatim.
    Original-team app groups, APNs and keychain values are not imported.
    """
    entitlements = plistlib.loads(plistlib.dumps(profile['Entitlements']))
    application_id = entitlements['application-identifier']
    if application_id.split('.', 1)[1] != identifier: raise RuntimeError('Entitlement identity mismatch')
    prefix = application_id.split('.', 1)[0]
    groups = entitlements.get('keychain-access-groups')
    if groups is not None:
        if not isinstance(groups, list) or not groups: raise RuntimeError('Invalid profile keychain grants')
        concrete = []
        for group in groups:
            if group == prefix + '.*': group = application_id
            if group not in (application_id, prefix + '.' + ROOT_ID): raise RuntimeError('Unapproved profile keychain scope')
            if group not in concrete: concrete.append(group)
        entitlements['keychain-access-groups'] = concrete
    def has_wildcard(value):
        if isinstance(value, str): return '*' in value
        if isinstance(value, dict): return any(has_wildcard(v) for v in value.values())
        if isinstance(value, list): return any(has_wildcard(v) for v in value)
        return False
    if has_wildcard(entitlements): raise RuntimeError('Unsupported wildcard profile entitlement')
    return entitlements


def existing_wildcard_entitlements(profile, identifier):
    if identifier not in {ROOT_ID + suffix for suffix in SAFE_SUFFIXES}:
        raise RuntimeError('Unapproved wildcard signing bundle scope')
    candidate = plistlib.loads(plistlib.dumps(profile))
    application_id = candidate['Entitlements'].get('application-identifier', '')
    if not isinstance(application_id, str) or '.' not in application_id:
        raise RuntimeError('Invalid wildcard profile identity')
    prefix, grant = application_id.split('.', 1)
    if '*' not in grant or not apple_identifier_grant_matches(grant, identifier):
        raise RuntimeError('Wildcard profile does not authorize this scoped app')
    candidate['Entitlements']['application-identifier'] = prefix + '.' + identifier
    entitlements = concrete_entitlements(candidate, identifier)
    def imports_original_identity(value):
        if isinstance(value, str): return PREFIX in value
        if isinstance(value, dict): return any(imports_original_identity(v) for v in value.values())
        if isinstance(value, list): return any(imports_original_identity(v) for v in value)
        return False
    if imports_original_identity(entitlements): raise RuntimeError('Original BeReal identity is not allowed in signing entitlements')
    return entitlements


def select_existing_wildcard_profile(api, der, team, device):
    """Select a fully verified existing grant using GETs only; no fallback POST."""
    resources = api.collection('/v1/profiles', {
        'fields[profiles]': 'uuid,profileType,profileState,profileContent,expirationDate'})
    resources.sort(key=lambda item: item.get('attributes', {}).get('expirationDate', ''), reverse=True)
    expected = {ROOT_ID + suffix for suffix in SAFE_SUFFIXES}
    for resource in resources:
        attributes = resource.get('attributes', {})
        if attributes.get('profileType') != 'IOS_APP_ADHOC' or attributes.get('profileState') != 'ACTIVE': continue
        if not attributes.get('profileContent'):
            resource = api.request('GET', '/v1/profiles/' + resource['id'])['data']
        try:
            compatibility = probe_profile_compatibility(resource, der, team, device['attributes']['udid'])
            if compatibility['application_identifier_kind'] != 'wildcard' or set(compatibility['compatible_scoped_identifiers']) != expected: continue
            raw = helper.decode_base64(resource['attributes']['profileContent'])
            profile = plistlib.loads(run(['openssl', 'cms', '-verify', '-inform', 'DER', '-noverify'], raw))
            for identifier in expected: existing_wildcard_entitlements(profile, identifier)
            return raw, profile
        except (RuntimeError, KeyError, ValueError, TypeError): continue
    raise RuntimeError('No existing wildcard Ad Hoc profile proves certificate, team, registered-device and all-five-bundle compatibility; no Apple resources were changed')


def get_profile(api, certificate, der, team, identifier, device):
    if identifier not in {ROOT_ID + suffix for suffix in SAFE_SUFFIXES}: raise RuntimeError('Unapproved bundle scope')
    bundles = api.collection('/v1/bundleIds', {'filter[platform]': 'IOS', 'filter[identifier]': identifier})
    if len(bundles) > 1: raise RuntimeError('Ambiguous bundle registration')
    bundle = bundles[0] if bundles else api.request('POST', '/v1/bundleIds', {'data': {'type': 'bundleIds', 'attributes': {'name': 'BeReal493 ' + identifier.rsplit('.', 1)[-1], 'identifier': identifier, 'platform': 'IOS'}}})['data']
    if bundle.get('attributes', {}).get('identifier') != identifier or bundle.get('attributes', {}).get('platform') != 'IOS': raise RuntimeError('Unexpected bundle registration')
    candidates = api.collection('/v1/bundleIds/' + bundle['id'] + '/profiles', {'fields[profiles]': 'name,uuid,profileType,profileState,profileContent,expirationDate'})
    candidates = [p for p in candidates if p.get('attributes', {}).get('profileType') == 'IOS_APP_ADHOC' and p.get('attributes', {}).get('profileState') == 'ACTIVE']
    for candidate in candidates:
        # An API read failure must propagate; it is not proof that an existing
        # profile is unusable and must not silently create a duplicate profile.
        if not candidate['attributes'].get('profileContent'): candidate = api.request('GET', '/v1/profiles/' + candidate['id'])['data']
        try:
            return validate_profile(candidate, der, team, identifier, device['attributes']['udid'])
        except (RuntimeError, KeyError, ValueError, TypeError): continue
    created = api.request('POST', '/v1/profiles', {'data': {
        'type': 'profiles', 'attributes': {'name': 'BeReal493-AdHoc-' + identifier.rsplit('.', 1)[-1], 'profileType': 'IOS_APP_ADHOC'},
        'relationships': {'bundleId': {'data': {'type': 'bundleIds', 'id': bundle['id']}},
                          'certificates': {'data': [{'type': 'certificates', 'id': certificate['id']}]},
                          'devices': {'data': [{'type': 'devices', 'id': device['id']}]}}
    }})['data']
    if not created['attributes'].get('profileContent'): created = api.request('GET', '/v1/profiles/' + created['id'])['data']
    return validate_profile(created, der, team, identifier, device['attributes']['udid'])


def public_profile_receipt(identifier, profile, der, use_existing_wildcard=False):
    expiration = profile['ExpirationDate']
    if expiration.tzinfo is None: expiration = expiration.replace(tzinfo=datetime.timezone.utc)
    return {'bundle_identifier': identifier, 'profile_uuid': profile['UUID'],
            'expiration_date': expiration.astimezone(datetime.timezone.utc).isoformat().replace('+00:00', 'Z'),
            'certificate_sha256': hashlib.sha256(der).hexdigest(),
            'provisioned_device_count': len(profile['ProvisionedDevices']),
            'entitlement_keys': sorted(existing_wildcard_entitlements(profile, identifier) if use_existing_wildcard else concrete_entitlements(profile, identifier))}


def prepare_profiles(root, der, api, certificate, device):
    profiles = []
    for suffix in SAFE_SUFFIXES:
        identifier = ROOT_ID + suffix
        _, profile = get_profile(api, certificate, der, os.environ['APPLE_TEAM_ID'], identifier, device)
        profiles.append(public_profile_receipt(identifier, profile, der))
    output = Path('bereal-public'); output.mkdir(exist_ok=True)
    (output / 'signing-public-key.pem').write_bytes(run(['openssl', 'x509', '-inform', 'DER', '-pubkey', '-noout'], der))
    receipt = {'distribution_certificate_validated': True,
               'certificate_sha256': hashlib.sha256(der).hexdigest(),
               'distribution': 'IOS_APP_ADHOC', 'registered_device_count': 1,
               'provisioned_bundle_count': len(profiles), 'profiles': profiles,
               'signed_ipa_created': False, 'device_installation': 'not tested', 'posting': 'not tested'}
    (output / 'provisioning-readiness.json').write_text(json.dumps(receipt, indent=2) + '\n')
    print('Prepared and validated matching Ad Hoc profiles for all five scoped bundles and the one registered device.')
    print('Published only the public encryption key and provisioning receipt; no signed IPA was created.')


def apple_identifier_grant_matches(grant, identifier):
    """Apple wildcard identifiers are either '*' or a trailing '.*'."""
    if not isinstance(grant, str) or not isinstance(identifier, str): return False
    if '*' not in grant: return grant == identifier
    if grant == '*': return bool(identifier)
    if grant.count('*') != 1 or not grant.endswith('.*'): return False
    return identifier.startswith(grant[:-1]) and len(identifier) > len(grant) - 1


def probe_profile_compatibility(resource, der, team, udid):
    """Read-only analysis; never returns raw profile bytes or device identifiers.

    This deliberately does not change strict exact-App-ID signing validation.
    Wildcard candidates are entitlement-level evidence for a later explicit
    implementation and still require real signing/install verification.
    """
    attributes = resource.get('attributes', {})
    if attributes.get('profileType') != 'IOS_APP_ADHOC' or attributes.get('profileState') != 'ACTIVE':
        raise RuntimeError('Incorrect profile distribution type or state')
    raw = helper.decode_base64(attributes.get('profileContent', ''))
    if not raw or len(raw) > 10 * 1024 * 1024: raise RuntimeError('Invalid profile content')
    profile = plistlib.loads(run(['openssl', 'cms', '-verify', '-inform', 'DER', '-noverify'], raw))
    grants = profile.get('Entitlements', {})
    application_id = grants.get('application-identifier', '')
    if not isinstance(application_id, str) or '.' not in application_id: raise RuntimeError('Profile identity is missing')
    prefix, identifier_grant = application_id.split('.', 1)
    if team not in profile.get('TeamIdentifier', []) or prefix not in profile.get('ApplicationIdentifierPrefix', []):
        raise RuntimeError('Profile team or prefix mismatch')
    if grants.get('com.apple.developer.team-identifier') != team or grants.get('get-task-allow') is not False:
        raise RuntimeError('Profile entitlement mismatch')
    if der not in profile.get('DeveloperCertificates', []) or not helper.is_future(profile.get('ExpirationDate')) or not helper.is_future(attributes.get('expirationDate')):
        raise RuntimeError('Profile certificate/expiry mismatch')
    if profile.get('ProvisionedDevices') != [udid] or profile.get('ProvisionsAllDevices'):
        raise RuntimeError('Profile does not target only the registered device')
    try: profile_uuid = str(uuid.UUID(profile.get('UUID', '')))
    except (ValueError, AttributeError, TypeError): raise RuntimeError('Invalid profile UUID') from None
    if attributes.get('uuid', '').lower() != profile_uuid: raise RuntimeError('Profile UUID differs from Apple metadata')
    identifiers = []
    for suffix in SAFE_SUFFIXES:
        identifier = ROOT_ID + suffix
        if not apple_identifier_grant_matches(identifier_grant, identifier): continue
        candidate = plistlib.loads(plistlib.dumps(profile))
        entitlements = candidate['Entitlements']
        concrete_application_id = prefix + '.' + identifier
        entitlements['application-identifier'] = concrete_application_id
        if 'keychain-access-groups' in entitlements:
            keychain_grants = entitlements['keychain-access-groups']
            if not isinstance(keychain_grants, list) or not any(apple_identifier_grant_matches(grant, concrete_application_id) for grant in keychain_grants):
                continue
            entitlements['keychain-access-groups'] = [concrete_application_id]
        try: concrete_entitlements(candidate, identifier)
        except (RuntimeError, KeyError, TypeError, ValueError): continue
        identifiers.append(identifier)
    expiration = profile['ExpirationDate']
    if expiration.tzinfo is None: expiration = expiration.replace(tzinfo=datetime.timezone.utc)
    return {'profile_uuid': profile_uuid, 'distribution': 'IOS_APP_ADHOC',
            'application_identifier_kind': 'wildcard' if '*' in identifier_grant else 'explicit',
            'compatible_scoped_identifiers': identifiers,
            'expiration_date': expiration.astimezone(datetime.timezone.utc).isoformat().replace('+00:00', 'Z'),
            'certificate_sha256': hashlib.sha256(der).hexdigest(),
            'provisioned_device_count': 1}


def probe_existing_profiles(der, api, device):
    resources = api.collection('/v1/profiles', {
        'fields[profiles]': 'uuid,profileType,profileState,profileContent,expirationDate'})
    distribution_types = {}
    candidates, validated, incompatible = [], 0, 0
    active_adhoc = 0
    for resource in resources:
        attributes = resource.get('attributes', {})
        distribution = attributes.get('profileType', '')
        if isinstance(distribution, str) and re.fullmatch('[A-Z_]{1,60}', distribution):
            distribution_types[distribution] = distribution_types.get(distribution, 0) + 1
        if distribution != 'IOS_APP_ADHOC' or attributes.get('profileState') != 'ACTIVE': continue
        active_adhoc += 1
        # GET failures propagate. This probe never creates replacement assets.
        if not attributes.get('profileContent'):
            resource = api.request('GET', '/v1/profiles/' + resource['id'])['data']
        try:
            result = probe_profile_compatibility(resource, der, os.environ['APPLE_TEAM_ID'], device['attributes']['udid'])
        except (RuntimeError, KeyError, ValueError, TypeError):
            incompatible += 1
            continue
        validated += 1
        if result['compatible_scoped_identifiers']: candidates.append(result)
    covered = sorted({identifier for candidate in candidates for identifier in candidate['compatible_scoped_identifiers']})
    receipt = {'mode': 'read_only_existing_profile_probe', 'distribution_certificate_validated': True,
               'certificate_sha256': hashlib.sha256(der).hexdigest(), 'registered_device_count': 1,
               'catalog_profile_count': len(resources), 'catalog_distribution_types': distribution_types,
               'active_ios_adhoc_profile_count': active_adhoc,
               'validated_cert_team_device_profile_count': validated,
               'rejected_ios_adhoc_profile_count': incompatible,
               'compatible_profile_count': len(candidates), 'compatible_profiles': candidates,
               'covered_scoped_identifiers': covered,
               'all_five_scoped_identifiers_covered': len(covered) == len(SAFE_SUFFIXES),
               'compatibility': 'CMS, metadata and concrete-entitlement analysis only; strict signing flow unchanged',
               'apple_resources_created_or_modified': False, 'signed_ipa_created': False,
               'device_installation': 'not tested', 'posting': 'not tested'}
    output = Path('bereal-public'); output.mkdir(exist_ok=True)
    (output / 'existing-profile-probe.json').write_text(json.dumps(receipt, indent=2) + '\n')
    (output / 'signing-public-key.pem').write_bytes(run(['openssl', 'x509', '-inform', 'DER', '-pubkey', '-noout'], der))
    print('Read-only existing-profile probe completed. Compatible Ad Hoc profile count: ' + str(len(candidates)))
    print('Scoped bundle coverage: ' + str(len(covered)) + '/5. No Apple resources were created or modified.')
    print('Published only the public encryption key and safe compatibility receipt; no signed IPA was created.')


def build_adapter(root, original):
    archive = root / 'source.zip'
    download(f'https://github.com/444yttt/BeReal493/archive/{SOURCE_COMMIT}.zip', archive)
    source_root = root / 'source'; extract(archive, source_root)
    source = source_root / ('BeReal493-' + SOURCE_COMMIT)
    sdk = run(['xcrun', '--sdk', 'iphoneos', '--show-sdk-path']).decode().strip()
    library = root / 'CameraRollAdapter.dylib'
    run(['xcrun', '--sdk', 'iphoneos', 'clang', '-dynamiclib', '-arch', 'arm64', '-isysroot', sdk, '-miphoneos-version-min=17.0', '-fobjc-arc', '-fmodules', '-O2', '-framework', 'UIKit', '-framework', 'PhotosUI', '-framework', 'AVFoundation', '-install_name', '@executable_path/Frameworks/CameraRollAdapter.dylib', str(source / 'CameraRollAdapter.m'), str(source / 'BRPairState.m'), '-o', str(library)])
    unsigned = root / 'unsigned.ipa'
    run([sys.executable, str(source / 'scripts/package_ipa.py'), str(original), str(library), str(unsigned)])
    payload = root / 'payload'; extract(unsigned, payload)
    return payload


def encrypt_delivery(root, files, output):
    delivery = root / 'delivery.zip'
    with zipfile.ZipFile(delivery, 'w', compression=zipfile.ZIP_STORED) as archive:
        for path in files: archive.write(path, path.name)
    output.parent.mkdir(exist_ok=True)
    run(['openssl', 'cms', '-encrypt', '-aes-256-gcm', '-binary', '-in', str(delivery), '-outform', 'DER', '-out', str(output), 'delivery-recipient.pem'])


def prepare_input(root, original, der):
    # Persist the recovered input before compilation, so a toolchain failure
    # cannot force another download from an expiring access URL.
    encrypt_persistent_input(root, original, der)
    payload = build_adapter(root, original)
    unsigned = root / 'unsigned.ipa'
    unsigned.rename(root / 'BeReal493-CameraRoll-UNSIGNED.ipa')
    unsigned = root / 'BeReal493-CameraRoll-UNSIGNED.ipa'
    source = root / 'source' / ('BeReal493-' + SOURCE_COMMIT)
    inspection = json.loads(run([sys.executable, str(source / 'scripts/inspect_ipa.py'), str(unsigned)]))
    verification = {'file': unsigned.name, 'sha256': sha256_file(unsigned),
                    'input_sha256': ORIGINAL_SHA, 'source_commit': SOURCE_COMMIT,
                    'certificate_sha256': hashlib.sha256(der).hexdigest(),
                    'adapter': 'implemented; rebuilt from pinned source; not device tested',
                    'archive_inspection': inspection, 'signature': 'unsigned',
                    'apple_resources_created_or_modified': False,
                    'device_installation': 'not tested', 'posting': 'not tested'}
    receipt = private(root / 'unsigned-verification.json', (json.dumps(verification, indent=2) + '\n').encode())
    encrypt_delivery(root, [unsigned, receipt], Path('bereal-output/BeReal493-unsigned-delivery.cms'))
    print('Pinned adapter rebuilt and unsigned IPA encrypted for structural review. SHA256: ' + verification['sha256'])
    print('No Apple resources were created or modified. No signed IPA was created.')


def main(argv=None):
    global helper
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument('--prepare-profiles', action='store_true', help='Provision the scoped Ad Hoc bundles without input IPA or signing output')
    modes.add_argument('--probe-existing-profiles', action='store_true', help='Read-only scan of existing profiles for scoped exact/wildcard Ad Hoc coverage')
    modes.add_argument('--prepare-input', action='store_true', help='Recover and persist encrypted input, rebuild adapter, and encrypt unsigned IPA without provisioning or signing')
    modes.add_argument('--verify-input', action='store_true', help='Restore and exact-hash-check input only, without rebuilding, provisioning, signing or output binaries')
    modes.add_argument('--use-existing-wildcard-profiles', action='store_true', help='Sign with an independently validated alternate existing CI identity and wildcard profile, without Apple writes')
    options = parser.parse_args(argv)
    if os.environ.get('GITHUB_REPOSITORY') != '444yttt/Y3POSClient' or os.environ.get('GITHUB_REF') != 'refs/heads/main':
        raise RuntimeError('This job may only use the authorized main repository scope')
    if sys.version_info < (3, 11): raise RuntimeError('Python 3.11 or newer is required by the pinned packaging source')
    configure_openssl()
    helper = load_helper()
    needs_input = not (options.prepare_profiles or options.probe_existing_profiles)
    envelope = json.loads(Path('bereal-signing-input.json').read_text()) if needs_input else None
    with tempfile.TemporaryDirectory(prefix='bereal-resign-', dir=os.environ['RUNNER_TEMP']) as directory:
        root = Path(directory)
        p12, der, key, asc = decode_identity(root, need_private_key=needs_input)
        input_recipient_der = der
        signing_password_env = 'P12_PASSWORD'
        api = RefreshingAppleAPI(asc)
        certificate, device = signing_readiness(api, der)
        if options.probe_existing_profiles:
            probe_existing_profiles(der, api, device)
            return
        if options.prepare_profiles:
            prepare_profiles(root, der, api, certificate, device)
            return
        existing_profile = None
        if options.use_existing_wildcard_profiles:
            alternate = root / 'alternate-signing'; alternate.mkdir(mode=0o700)
            p12, der, _, _ = decode_identity(alternate, need_private_key=False,
                certificate_env='DIST_P12_BASE64', password_env='DIST_P12_PASSWORD')
            _, alternate_device = signing_readiness(api, der)
            if alternate_device['attributes']['udid'] != device['attributes']['udid']:
                raise RuntimeError('Registered device changed during alternate signing preflight')
            existing_profile = select_existing_wildcard_profile(api, der, os.environ['APPLE_TEAM_ID'], device)
            signing_password_env = 'DIST_P12_PASSWORD'
            print('Alternate distribution certificate and existing wildcard Ad Hoc profile validated for all five scoped bundles. No Apple resources were changed.')
        original = decrypt_input(root, key, envelope)
        if options.verify_input:
            output = Path('bereal-public'); output.mkdir(exist_ok=True)
            verification = {'mode': 'input_verification_only', 'input_sha256': ORIGINAL_SHA,
                'input_bytes': original.stat().st_size, 'source_commit': SOURCE_COMMIT,
                'envelope_version': envelope['version'], 'input_sha256_verified': True,
                'input_recipient_certificate_sha256': hashlib.sha256(input_recipient_der).hexdigest(),
                'apple_resources_created_or_modified': False, 'signed_ipa_created': False}
            (output / 'input-verification.json').write_text(json.dumps(verification, indent=2) + '\n')
            print('Original input restored and its exact SHA256 verified. No rebuild, signing or Apple resource changes were performed.')
            return
        if options.prepare_input:
            prepare_input(root, original, der)
            return
        payload = build_adapter(root, original)
        app = payload / 'Payload/BeReal.app'
        bundles = [app] + sorted((app / 'PlugIns').glob('*.appex'))
        mappings = {}; targets = []
        expected_identifiers = {PREFIX + suffix for suffix in SAFE_SUFFIXES}
        for bundle in bundles:
            info_path = bundle / 'Info.plist'; info = plistlib.loads(info_path.read_bytes())
            old = info['CFBundleIdentifier']; suffix = old[len(PREFIX):] if old.startswith(PREFIX) else None
            if suffix not in SAFE_SUFFIXES or old not in expected_identifiers: raise RuntimeError('Unexpected app or extension')
            expected_identifiers.remove(old)
            executable = info.get('CFBundleExecutable', '')
            if not executable or Path(executable).name != executable or not (bundle / executable).is_file(): raise RuntimeError('Invalid bundle executable')
            (bundle / executable).chmod(0o755)
            identifier = ROOT_ID + suffix
            raw, profile = existing_profile if existing_profile else get_profile(api, certificate, der, os.environ['APPLE_TEAM_ID'], identifier, device)
            info['CFBundleIdentifier'] = identifier
            info_path.write_bytes(plistlib.dumps(info))
            private(bundle / 'embedded.mobileprovision', raw)
            entitlements = existing_wildcard_entitlements(profile, identifier) if existing_profile else concrete_entitlements(profile, identifier)
            private(root / ('entitlements-' + str(len(targets)) + '.plist'), plistlib.dumps(entitlements))
            targets.append((bundle, info, profile, root / ('entitlements-' + str(len(targets)) + '.plist')))
            mappings[old] = identifier
        if expected_identifiers: raise RuntimeError('Expected the root app and all four extensions')
        # Change only explicit containing-app references, preserving OAuth URL schemes.
        def remap(value):
            if isinstance(value, dict): return {k: remap(v) if k in ('WKAppBundleIdentifier', 'WKCompanionAppBundleIdentifier') or isinstance(v, (dict, list)) else v for k,v in value.items()}
            if isinstance(value, list): return [remap(v) for v in value]
            return mappings.get(value, value) if isinstance(value, str) else value
        for bundle, info, profile, ent in targets: (bundle / 'Info.plist').write_bytes(plistlib.dumps(remap(info)))
        print('Prepared matching Ad Hoc profiles for the root app and four extensions.')
        keychain = root / 'signing.keychain-db'; password = secrets.token_urlsafe(32)
        try:
            run(['/usr/bin/security', 'create-keychain', '-p', password, str(keychain)])
            run(['/usr/bin/security', 'set-keychain-settings', '-lut', '21600', str(keychain)])
            run(['/usr/bin/security', 'unlock-keychain', '-p', password, str(keychain)])
            run(['/usr/bin/security', 'import', str(p12), '-P', os.environ[signing_password_env], '-t', 'cert', '-f', 'pkcs12', '-k', str(keychain), '-T', '/usr/bin/codesign', '-T', '/usr/bin/security'])
            run(['/usr/bin/security', 'set-key-partition-list', '-S', 'apple-tool:,apple:,codesign:', '-s', '-k', password, str(keychain)])
            fingerprint = hashlib.sha1(der).hexdigest().upper()
            identities = run(['/usr/bin/security', 'find-identity', '-v', '-p', 'codesigning', str(keychain)])
            if fingerprint.encode() not in identities: raise RuntimeError('Imported identity is not valid for code signing')
            def sign(path, entitlements=None):
                args = ['/usr/bin/codesign', '--force', '--sign', fingerprint, '--keychain', str(keychain), '--timestamp=none', '--generate-entitlement-der']
                if entitlements: args += ['--entitlements', str(entitlements)]
                run(args + [str(path)])
            app_executables = {bundle / info['CFBundleExecutable'] for bundle,info,profile,ent in targets}
            macho_count = len(app_executables)
            for path in sorted(app.rglob('*'), key=lambda p:len(p.parts), reverse=True):
                if path.is_file() and path not in app_executables:
                    with path.open('rb') as stream: magic = stream.read(4)
                    if magic in (b'\xcf\xfa\xed\xfe', b'\xfe\xed\xfa\xcf', b'\xce\xfa\xed\xfe', b'\xfe\xed\xfa\xce', b'\xca\xfe\xba\xbe', b'\xbe\xba\xfe\xca', b'\xca\xfe\xba\xbf', b'\xbf\xba\xfe\xca'):
                        sign(path); macho_count += 1
            for framework in sorted(app.rglob('*.framework'), key=lambda p:len(p.parts), reverse=True): sign(framework)
            for bundle,info,profile,ent in sorted(targets,key=lambda t:len(t[0].parts),reverse=True): sign(bundle,ent)
            run(['/usr/bin/codesign', '--verify', '--deep', '--strict', str(app)])
            for bundle,info,profile,ent in targets:
                run(['/usr/bin/codesign', '--verify', '--strict', str(bundle)])
                actual = plistlib.loads(run(['/usr/bin/codesign', '-d', '--entitlements', ':-', str(bundle)]))
                if actual != plistlib.loads(ent.read_bytes()): raise RuntimeError('Signed entitlements differ from verified profile')
                certificate_prefix = root / ('verified-cert-' + str(targets.index((bundle,info,profile,ent))) + '-')
                run(['/usr/bin/codesign', '-d', '--extract-certificates', str(certificate_prefix), str(bundle)])
                if Path(str(certificate_prefix) + '0').read_bytes() != der: raise RuntimeError('Signed bundle certificate differs from the approved identity')
        finally:
            subprocess.run(['/usr/bin/security', 'delete-keychain', str(keychain)], capture_output=True)
        ipa = root / 'BeReal493-CameraRoll-SIGNED.ipa'
        with zipfile.ZipFile(ipa,'w',compression=zipfile.ZIP_DEFLATED,compresslevel=6) as archive:
            for path in sorted((payload / 'Payload').rglob('*')):
                if path.is_file(): archive.write(path,path.relative_to(payload))
        with zipfile.ZipFile(ipa) as archive:
            if archive.testzip() is not None: raise RuntimeError('Signed IPA archive verification failed')
        digest = sha256_file(ipa)
        verification = {'file':ipa.name,'sha256':digest,'source_commit':SOURCE_COMMIT,'input_sha256':ORIGINAL_SHA,'bundle_identifier':ROOT_ID,'distribution':'IOS_APP_ADHOC','registered_device_count':1,'provisioned_bundle_count':len(targets),'distinct_profile_count':len({profile['UUID'] for bundle,info,profile,ent in targets}),'profile_selection':'existing_wildcard_read_only' if existing_profile else 'exact_scoped_profiles','signed_macho_count':macho_count,'certificate_sha256':hashlib.sha256(der).hexdigest(),'input_recipient_certificate_sha256':hashlib.sha256(input_recipient_der).hexdigest(),'profiles':[public_profile_receipt(info['CFBundleIdentifier'],profile,der,bool(existing_profile)) for bundle,info,profile,ent in targets],'signature_verification':'codesign deep strict passed; each app/extension matched concrete profile entitlements and the approved certificate','device_installation':'not tested','posting':'not tested'}
        receipt = private(root / 'verification.json', (json.dumps(verification,indent=2)+'\n').encode())
        encrypt_delivery(root, [ipa, receipt], Path('bereal-output/BeReal493-signed-delivery.cms'))
        print('Signed IPA verified and encrypted for the recipient. SHA256: ' + digest)
        print('No device installation or posting test was performed.')


if __name__ == '__main__':
    try: main()
    except Exception as error:
        print('BeReal signing failed: ' + (str(error) if isinstance(error,RuntimeError) else type(error).__name__),file=sys.stderr);sys.exit(1)
