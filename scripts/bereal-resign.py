#!/usr/bin/env python3
"""Scoped Ad Hoc signing inside Y3POSClient. Private assets never leave the runner."""
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
import urllib.request
import zipfile

ORIGINAL_SHA = 'e7d77665740c61f2b0d6eae21cb6052acd2add364db3f6b5fc9ef9198ac31cbc'
SOURCE_COMMIT = '1f749cd1b2433d2a32694d5c91849d22f84f429f'
ROOT_ID = 'com.ayato.bereal493'
PREFIX = 'AlexisBarreyat.BeReal'
SAFE_SUFFIXES = ('', '.iMessageExtension', '.RealMojiNotificationContentExtension', '.NotificationServiceExtension', '.Widgets')

spec = importlib.util.spec_from_file_location('existing_helper', Path(__file__).with_name('prepare-ci-profile.py'))
helper = importlib.util.module_from_spec(spec); spec.loader.exec_module(helper)


def run(args, data=None):
    result = subprocess.run(args, input=data, capture_output=True)
    if result.returncode:
        raise RuntimeError('A signing/tool command failed: ' + Path(args[0]).name)
    return result.stdout


def private(path, data):
    path.write_bytes(data); path.chmod(0o600); return path


def download(url, path):
    if not url.startswith('https://'):
        raise RuntimeError('HTTPS input is required')
    with urllib.request.urlopen(url, timeout=120) as response, path.open('wb') as target:
        while chunk := response.read(1048576): target.write(chunk)


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


def decode_identity(root):
    required = ['BUILD_CERTIFICATE_BASE64', 'P12_PASSWORD', 'APPLE_TEAM_ID', 'ASC_KEY_ID', 'ASC_ISSUER_ID', 'ASC_PRIVATE_KEY']
    if any(not os.environ.get(name) for name in required): raise RuntimeError('Required existing signing assets are missing')
    p12 = private(root / 'identity.p12', base64.b64decode(''.join(os.environ['BUILD_CERTIFICATE_BASE64'].split()), validate=True))
    pem = run(['openssl', 'pkcs12', '-in', str(p12), '-passin', 'env:P12_PASSWORD', '-clcerts', '-nokeys'])
    certificates = re.findall(br'-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----', pem, re.S)
    if len(certificates) != 1: raise RuntimeError('Expected one certificate')
    der = ssl.PEM_cert_to_DER_cert(certificates[0].decode())
    key = private(root / 'signing-private.pem', run(['openssl', 'pkcs12', '-in', str(p12), '-passin', 'env:P12_PASSWORD', '-nocerts', '-nodes']))
    public_from_key = run(['openssl', 'pkey', '-in', str(key), '-pubout', '-outform', 'DER'])
    public_from_cert = run(['openssl', 'x509', '-inform', 'DER', '-pubkey', '-noout'], der)
    public_from_cert = run(['openssl', 'pkey', '-pubin', '-outform', 'DER'], public_from_cert)
    if public_from_key != public_from_cert: raise RuntimeError('Certificate/private-key mismatch')
    run(['openssl', 'x509', '-inform', 'DER', '-noout', '-checkend', '0'], der)
    asc = private(root / 'AuthKey.p8', (os.environ['ASC_PRIVATE_KEY'].replace('\\n', '\n').strip() + '\n').encode())
    return p12, der, key, asc


def decrypt_input(root, key, envelope):
    if envelope.get('version') != 1 or envelope.get('input_sha256') != ORIGINAL_SHA or envelope.get('source_commit') != SOURCE_COMMIT:
        raise RuntimeError('Unexpected encrypted input contract')
    commit = envelope.get('transfer_commit', '')
    if not re.fullmatch('[0-9a-f]{40}', commit): raise RuntimeError('Pinned transfer commit is required')
    wrapped = private(root / 'wrapped-keys.bin', base64.b64decode(envelope['wrapped_keys'], validate=True))
    keys = run(['openssl', 'pkeyutl', '-decrypt', '-inkey', str(key), '-in', str(wrapped), '-pkeyopt', 'rsa_padding_mode:oaep', '-pkeyopt', 'rsa_oaep_md:sha256', '-pkeyopt', 'rsa_mgf1_md:sha256'])
    if len(keys) != 64: raise RuntimeError('Invalid decrypted transfer key')
    iv = base64.b64decode(envelope['iv'], validate=True)
    if len(iv) != 16: raise RuntimeError('Invalid IV')
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
    with original.open('rb') as stream:
        if hashlib.file_digest(stream, 'sha256').hexdigest() != ORIGINAL_SHA: raise RuntimeError('Original IPA hash mismatch')
    print('Encrypted original IPA restored and its exact hash verified.')
    return original


def get_profile(api, certificate, der, team, identifier, device):
    if identifier not in {ROOT_ID + suffix for suffix in SAFE_SUFFIXES}: raise RuntimeError('Unapproved bundle scope')
    bundles = api.collection('/v1/bundleIds', {'filter[platform]': 'IOS', 'filter[identifier]': identifier})
    if len(bundles) > 1: raise RuntimeError('Ambiguous bundle registration')
    bundle = bundles[0] if bundles else api.request('POST', '/v1/bundleIds', {'data': {'type': 'bundleIds', 'attributes': {'name': 'BeReal493 ' + identifier.rsplit('.', 1)[-1], 'identifier': identifier, 'platform': 'IOS'}}})['data']
    if bundle.get('attributes', {}).get('identifier') != identifier: raise RuntimeError('Unexpected bundle registration')
    candidates = api.collection('/v1/bundleIds/' + bundle['id'] + '/profiles', {'fields[profiles]': 'name,uuid,profileType,profileState,profileContent,expirationDate'})
    candidates = [p for p in candidates if p.get('attributes', {}).get('profileType') == 'IOS_APP_ADHOC' and p.get('attributes', {}).get('profileState') == 'ACTIVE']
    def validate(resource):
        attributes = resource['attributes']
        raw = helper.decode_base64(attributes['profileContent'])
        decoded = plistlib.loads(run(['openssl', 'cms', '-verify', '-inform', 'DER', '-noverify'], raw))
        entitlements = decoded['Entitlements']
        prefix, allowed = entitlements.get('application-identifier', '').split('.', 1)
        if allowed != identifier or team not in decoded.get('TeamIdentifier', []): raise RuntimeError('Profile identity mismatch')
        if prefix not in decoded.get('ApplicationIdentifierPrefix', []): raise RuntimeError('Profile prefix mismatch')
        if entitlements.get('com.apple.developer.team-identifier') != team or entitlements.get('get-task-allow') is not False: raise RuntimeError('Profile entitlement mismatch')
        if der not in decoded.get('DeveloperCertificates', []) or not helper.is_future(decoded.get('ExpirationDate')): raise RuntimeError('Profile certificate/expiry mismatch')
        if decoded.get('ProvisionedDevices') != [device['attributes']['udid']] or decoded.get('ProvisionsAllDevices'): raise RuntimeError('Profile does not target only the registered device')
        if attributes.get('profileType') != 'IOS_APP_ADHOC': raise RuntimeError('Incorrect profile distribution type')
        return raw, decoded
    for candidate in candidates:
        try:
            if not candidate['attributes'].get('profileContent'): candidate = api.request('GET', '/v1/profiles/' + candidate['id'])['data']
            return validate(candidate)
        except RuntimeError: continue
    created = api.request('POST', '/v1/profiles', {'data': {
        'type': 'profiles', 'attributes': {'name': 'BeReal493-AdHoc-' + identifier.rsplit('.', 1)[-1], 'profileType': 'IOS_APP_ADHOC'},
        'relationships': {'bundleId': {'data': {'type': 'bundleIds', 'id': bundle['id']}},
                          'certificates': {'data': [{'type': 'certificates', 'id': certificate['id']}]},
                          'devices': {'data': [{'type': 'devices', 'id': device['id']}]}}
    }})['data']
    if not created['attributes'].get('profileContent'): created = api.request('GET', '/v1/profiles/' + created['id'])['data']
    return validate(created)


def build_adapter(root, original):
    archive = root / 'source.zip'
    download(f'https://github.com/444yttt/BeReal493/archive/{SOURCE_COMMIT}.zip', archive)
    source_root = root / 'source'; extract(archive, source_root)
    source = source_root / ('BeReal493-' + SOURCE_COMMIT)
    sdk = run(['xcrun', '--sdk', 'iphoneos', '--show-sdk-path']).decode().strip()
    library = root / 'CameraRollAdapter.dylib'
    run(['xcrun', '--sdk', 'iphoneos', 'clang', '-dynamiclib', '-arch', 'arm64', '-isysroot', sdk, '-miphoneos-version-min=17.0', '-fobjc-arc', '-fmodules', '-O2', '-framework', 'UIKit', '-framework', 'PhotosUI', '-framework', 'AVFoundation', '-install_name', '@executable_path/Frameworks/CameraRollAdapter.dylib', str(source / 'CameraRollAdapter.m'), str(source / 'BRPairState.m'), '-o', str(library)])
    unsigned = root / 'unsigned.ipa'
    run(['python3', str(source / 'scripts/package_ipa.py'), str(original), str(library), str(unsigned)])
    payload = root / 'payload'; extract(unsigned, payload)
    return payload


def main():
    if os.environ.get('GITHUB_REPOSITORY') != '444yttt/Y3POSClient' or os.environ.get('GITHUB_REF') != 'refs/heads/main':
        raise RuntimeError('This job may only use the authorized main repository scope')
    envelope = json.loads(Path('bereal-signing-input.json').read_text())
    with tempfile.TemporaryDirectory(prefix='bereal-resign-', dir=os.environ['RUNNER_TEMP']) as directory:
        root = Path(directory)
        p12, der, key, asc = decode_identity(root)
        api = helper.AppleAPI(helper.make_jwt(os.environ['ASC_KEY_ID'], os.environ['ASC_ISSUER_ID'], asc))
        matches = [c for c in api.collection('/v1/certificates') if c.get('attributes', {}).get('certificateContent') and hashlib.sha256(helper.decode_base64(c['attributes']['certificateContent'])).digest() == hashlib.sha256(der).digest()]
        if len(matches) != 1 or matches[0]['attributes'].get('certificateType') not in ('IOS_DISTRIBUTION', 'DISTRIBUTION') or not helper.is_future(matches[0]['attributes'].get('expirationDate')):
            raise RuntimeError('Existing Apple distribution certificate is not valid')
        devices = api.collection('/v1/devices', {'filter[platform]': 'IOS', 'filter[status]': 'ENABLED'})
        if len(devices) != 1: raise RuntimeError('Expected exactly the one registered enabled iOS device')
        original = decrypt_input(root, key, envelope)
        payload = build_adapter(root, original)
        app = payload / 'Payload/BeReal.app'
        bundles = [app] + sorted((app / 'PlugIns').glob('*.appex'))
        mappings = {}; targets = []
        for bundle in bundles:
            info_path = bundle / 'Info.plist'; info = plistlib.loads(info_path.read_bytes())
            old = info['CFBundleIdentifier']; suffix = old[len(PREFIX):] if old.startswith(PREFIX) else None
            if suffix not in SAFE_SUFFIXES: raise RuntimeError('Unexpected app or extension')
            identifier = ROOT_ID + suffix
            raw, profile = get_profile(api, matches[0], der, os.environ['APPLE_TEAM_ID'], identifier, devices[0])
            info['CFBundleIdentifier'] = identifier
            info_path.write_bytes(plistlib.dumps(info))
            private(bundle / 'embedded.mobileprovision', raw)
            entitlements = dict(profile['Entitlements'])
            private(root / ('entitlements-' + str(len(targets)) + '.plist'), plistlib.dumps(entitlements))
            targets.append((bundle, info, profile, root / ('entitlements-' + str(len(targets)) + '.plist')))
            mappings[old] = identifier
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
            run(['/usr/bin/security', 'unlock-keychain', '-p', password, str(keychain)])
            run(['/usr/bin/security', 'import', str(p12), '-P', os.environ['P12_PASSWORD'], '-t', 'cert', '-f', 'pkcs12', '-k', str(keychain), '-T', '/usr/bin/codesign', '-T', '/usr/bin/security'])
            run(['/usr/bin/security', 'set-key-partition-list', '-S', 'apple-tool:,apple:,codesign:', '-s', '-k', password, str(keychain)])
            fingerprint = hashlib.sha1(der).hexdigest().upper()
            identities = run(['/usr/bin/security', 'find-identity', '-v', '-p', 'codesigning', str(keychain)])
            if fingerprint.encode() not in identities: raise RuntimeError('Imported identity is not valid for code signing')
            def sign(path, entitlements=None):
                args = ['/usr/bin/codesign', '--force', '--sign', fingerprint, '--keychain', str(keychain), '--timestamp=none', '--generate-entitlement-der']
                if entitlements: args += ['--entitlements', str(entitlements)]
                run(args + [str(path)])
            app_executables = {bundle / info['CFBundleExecutable'] for bundle,info,profile,ent in targets}
            for path in sorted(app.rglob('*'), key=lambda p:len(p.parts), reverse=True):
                if path.is_file() and path not in app_executables:
                    with path.open('rb') as stream: magic = stream.read(4)
                    if magic in (b'\xcf\xfa\xed\xfe', b'\xfe\xed\xfa\xcf', b'\xca\xfe\xba\xbe', b'\xbe\xba\xfe\xca'): sign(path)
            for framework in sorted(app.rglob('*.framework'), key=lambda p:len(p.parts), reverse=True): sign(framework)
            for bundle,info,profile,ent in sorted(targets,key=lambda t:len(t[0].parts),reverse=True): sign(bundle,ent)
            run(['/usr/bin/codesign', '--verify', '--deep', '--strict', str(app)])
            for bundle,info,profile,ent in targets:
                run(['/usr/bin/codesign', '--verify', '--strict', str(bundle)])
                actual = plistlib.loads(run(['/usr/bin/codesign', '-d', '--entitlements', ':-', str(bundle)]))
                if actual != plistlib.loads(ent.read_bytes()): raise RuntimeError('Signed entitlements differ from verified profile')
        finally:
            subprocess.run(['/usr/bin/security', 'delete-keychain', str(keychain)], capture_output=True)
        ipa = root / 'BeReal493-CameraRoll-SIGNED.ipa'
        with zipfile.ZipFile(ipa,'w',compression=zipfile.ZIP_DEFLATED,compresslevel=6) as archive:
            for path in sorted((payload / 'Payload').rglob('*')):
                if path.is_file(): archive.write(path,path.relative_to(payload))
        with ipa.open('rb') as stream: digest = hashlib.file_digest(stream,'sha256').hexdigest()
        verification = {'file':ipa.name,'sha256':digest,'source_commit':SOURCE_COMMIT,'input_sha256':ORIGINAL_SHA,'bundle_identifier':ROOT_ID,'distribution':'IOS_APP_ADHOC','registered_device_count':1,'provisioned_bundle_count':len(targets),'signature_verification':'codesign deep strict passed; each app/extension entitlements matched profile','device_installation':'not tested','posting':'not tested'}
        receipt = private(root / 'verification.json', (json.dumps(verification,indent=2)+'\n').encode())
        delivery = root / 'delivery.zip'
        with zipfile.ZipFile(delivery,'w',compression=zipfile.ZIP_STORED) as archive:
            archive.write(ipa,ipa.name); archive.write(receipt,receipt.name)
        output = Path('bereal-output'); output.mkdir(exist_ok=True)
        run(['openssl','cms','-encrypt','-aes-256-gcm','-binary','-in',str(delivery),'-outform','DER','-out',str(output/'BeReal493-signed-delivery.cms'),'delivery-recipient.pem'])
        print('Signed IPA verified and encrypted for the recipient. SHA256: ' + digest)
        print('No device installation or posting test was performed.')


if __name__ == '__main__':
    try: main()
    except helper.SigningError as error:
        print(str(error),file=sys.stderr); sys.exit(1)
    except Exception as error:
        print('BeReal signing failed: ' + (str(error) if isinstance(error,RuntimeError) else type(error).__name__),file=sys.stderr);sys.exit(1)
