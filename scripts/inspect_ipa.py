#!/usr/bin/env python3
"""Offline IPA metadata verification. Does not execute or alter third-party code."""
import argparse, json, plistlib, sys, zipfile, hashlib
from pathlib import Path

def inspect(path):
    with open(path,'rb') as stream:
        digest=hashlib.file_digest(stream,'sha256').hexdigest()
    with zipfile.ZipFile(path) as z:
        names = z.namelist()
        info_candidates = [n for n in names if n.startswith('Payload/') and n.count('/') == 2 and n.endswith('.app/Info.plist')]
        # Info.plist is Payload/<App>.app/Info.plist (two slashes)
        if len(info_candidates) != 1:
            raise ValueError(f'Expected one top-level application Info.plist; found {info_candidates}')
        info_path=info_candidates[0]
        info=plistlib.loads(z.read(info_path))
        executable = info.get('CFBundleExecutable')
        prefix=info_path.rsplit('/', 1)[0]
        exe_path=f'{prefix}/{executable}'
        if exe_path not in names: raise ValueError('Main executable not found')
        with z.open(exe_path) as f: header=f.read(4096)
        magic=header[:4].hex()
        if magic not in ('cffaedfe','feedfacf','cafebabe','bebafeca'):
            raise ValueError(f'Unexpected Mach-O header {magic}')
        result={
            'bundle_id':info.get('CFBundleIdentifier'), 'version':info.get('CFBundleShortVersionString'),
            'build':info.get('CFBundleVersion'), 'minimum_os':info.get('MinimumOSVersion'),
            'executable': executable, 'executable_bytes':z.getinfo(exe_path).file_size,
            'mach_o_magic_hex':magic, 'has_embedded_mobileprovision':f'{prefix}/embedded.mobileprovision' in names,
            'framework_count':len([n for n in names if n.startswith(prefix+'/Frameworks/') and n.endswith('.framework/Info.plist')]),
            'ipa_sha256':digest,
        }
        return result

if __name__=='__main__':
    a=argparse.ArgumentParser();a.add_argument('ipa');a.add_argument('--expect-version',default='4.93.0');a.add_argument('--expect-id',default='AlexisBarreyat.BeReal');opts=a.parse_args()
    try:
        r=inspect(opts.ipa);print(json.dumps(r,indent=2,ensure_ascii=False))
        if r['version']!=opts.expect_version or r['bundle_id']!=opts.expect_id:
            sys.exit('ERROR: app/version mismatch')
    except Exception as exc:sys.exit(f'ERROR: {exc}')
