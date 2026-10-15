#!/bin/bash
set -euo pipefail
umask 077
[[ "$(uname -s)" == Darwin ]] || { echo 'UIKit lifecycle tests require macOS/Xcode' >&2; exit 1; }
repository_root="$(cd "$(dirname "$0")/.." && pwd)"
fixture_temporary="$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/bereal493-ui.XXXXXX")"
cleanup_fixture() {
  if [[ -f "$fixture_temporary/simulator-udid" ]]; then
    IFS= read -r fixture_simulator < "$fixture_temporary/simulator-udid"
    xcrun simctl shutdown "$fixture_simulator" >/dev/null 2>&1 || true
    xcrun simctl delete "$fixture_simulator" >/dev/null 2>&1 || true
  fi
  rm -rf "$fixture_temporary"
}
trap cleanup_fixture EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
python3 - "$repository_root" "$fixture_temporary" <<'PY'
import json
import os
from pathlib import Path
import platform
import plistlib
import re
import secrets
import subprocess
import sys
import time

repository, temporary = map(Path, sys.argv[1:])
bundle_id = 'com.ayato.bereal493.ui-lifecycle-fixture'
nonce = secrets.token_hex(16)
output = repository / 'output'
output.mkdir(exist_ok=True)


def command(arguments, *, timeout=60, env=None):
    result = subprocess.run(arguments, capture_output=True, text=True, timeout=timeout, env=env)
    if result.returncode:
        # Inputs and compiler diagnostics belong only to the synthetic fixture.
        # Never run this driver with an original IPA or signing credentials.
        if 'clang' in arguments:
            print(result.stderr[-16000:], file=sys.stderr)
        raise RuntimeError('UIKit fixture command failed: ' + ' '.join(arguments[:3]))
    return result.stdout.strip()


def simctl(*arguments, **kwargs):
    return command(['xcrun', 'simctl', *arguments], **kwargs)


def version(value):
    return tuple(int(part) for part in re.findall(r'\d+', str(value)))


def launched_pid(value):
    matches = re.findall(r'^' + re.escape(bundle_id) + r':\s*(\d+)\s*$', value, re.MULTILINE)
    if len(matches) != 1:
        raise RuntimeError('Fixture launch did not identify one process')
    return int(matches[0])


print('UIKit fixture: resolving Simulator SDK before CoreSimulator startup (up to 180s per query)', flush=True)
sdk = command(['xcrun', '--sdk', 'iphonesimulator', '--show-sdk-path'], timeout=180)
sdk_version_text = command(['xcrun', '--sdk', 'iphonesimulator', '--show-sdk-version'], timeout=180)
if not re.fullmatch(r'\d+\.\d+(?:\.\d+)?', sdk_version_text):
    raise SystemExit('Simulator SDK did not report a valid numeric version')
sdk_version = version(sdk_version_text)[:2]
if sdk_version < (17, 0):
    raise SystemExit('UIKit fixture requires a Simulator SDK of iOS 17 or newer')
print('UIKit fixture: selected SDK ' + sdk_version_text + '; requiring installed iOS 17+ runtime no newer than its major/minor', flush=True)
print('UIKit fixture: waiting for cold CoreSimulator inventory (up to 180s)', flush=True)
listing = json.loads(simctl('list', '--json', timeout=180))
runtimes = sorted((item for item in listing.get('runtimes', [])
                   if item.get('isAvailable') and '.iOS-' in item.get('identifier', '')
                   and (17, 0) <= version(item.get('version', '0'))[:2] <= sdk_version),
                  key=lambda item: version(item.get('version', '0')), reverse=True)
device_types = {item['identifier']: item for item in listing.get('devicetypes', [])}
selected = None
for runtime in runtimes:
    templates = [item for item in listing.get('devices', {}).get(runtime['identifier'], [])
                 if item.get('isAvailable') and item.get('name', '').startswith('iPhone')]
    for template in templates:
        device_type = template.get('deviceTypeIdentifier')
        if not device_type:
            matches = [key for key, item in device_types.items() if item.get('name') == template['name']]
            device_type = matches[0] if len(matches) == 1 else None
        if device_type in device_types:
            selected = runtime, device_type
            break
    if selected:
        break
if not selected:
    raise SystemExit('No available iPhone runtime in the supported range iOS 17.0 through SDK '
                     + sdk_version_text + '; UIKit tests cannot be skipped and no runtime will be downloaded.')
runtime, device_type = selected
print('UIKit fixture: creating isolated simulator (up to 120s)', flush=True)
udid = simctl('create', 'BeReal493-UI-' + nonce[:8], device_type, runtime['identifier'], timeout=120)
if not re.fullmatch(r'[0-9A-Fa-f-]{36}', udid):
    raise SystemExit('Simulator creation did not return one UDID')
(temporary / 'simulator-udid').write_text(udid + '\n')
print('UIKit fixture: created isolated ' + runtime.get('name', 'iOS') + ' simulator', flush=True)
print('UIKit fixture: booting isolated simulator (120s request; 240s boot readiness)', flush=True)
simctl('boot', udid, timeout=120)
simctl('bootstatus', udid, '-b', timeout=240)

app = temporary / 'BeRealUIFixture.app'
app.mkdir()
info = {
    'CFBundleIdentifier': bundle_id, 'CFBundleExecutable': 'BeRealUIFixture',
    'CFBundleName': 'BeReal UI Fixture', 'CFBundlePackageType': 'APPL',
    'CFBundleInfoDictionaryVersion': '6.0',
    'CFBundleShortVersionString': '0', 'CFBundleVersion': '0',
    'CFBundleSupportedPlatforms': ['iPhoneSimulator'], 'MinimumOSVersion': '17.0',
    'LSRequiresIPhoneOS': True, 'UIDeviceFamily': [1], 'UILaunchScreen': {},
    'UISupportedInterfaceOrientations': ['UIInterfaceOrientationPortrait',
                                        'UIInterfaceOrientationLandscapeLeft',
                                        'UIInterfaceOrientationLandscapeRight'],
    'UIApplicationSceneManifest': {
        'UIApplicationSupportsMultipleScenes': False,
        'UISceneConfigurations': {'UIWindowSceneSessionRoleApplication': [{
            'UISceneConfigurationName': 'Fixture',
            'UISceneClassName': 'UIWindowScene',
            'UISceneDelegateClassName': 'BRUIFixtureSceneDelegate',
        }]},
    },
}
(app / 'Info.plist').write_bytes(plistlib.dumps(info))
architecture = platform.machine()
if architecture not in ('arm64', 'x86_64'):
    raise SystemExit('Unsupported Simulator host architecture')
command(['xcrun', '--sdk', 'iphonesimulator', 'clang',
         '-target', architecture + '-apple-ios17.0-simulator', '-isysroot', sdk,
         '-fobjc-arc', '-fmodules', '-O0', '-framework', 'UIKit',
         '-framework', 'PhotosUI', '-framework', 'AVFoundation', '-framework', 'CoreGraphics',
         str(repository / 'tests/ui_lifecycle.m'), str(repository / 'BRPairState.m'),
         '-o', str(app / 'BeRealUIFixture')], timeout=180)
command(['codesign', '--force', '--sign', '-', '--timestamp=none', str(app)])
simctl('install', udid, str(app), timeout=120)
container = Path(simctl('get_app_container', udid, bundle_id, 'data'))
environment = dict(os.environ, SIMCTL_CHILD_BRUI_TEST_NONCE=nonce)
initial_pid = launched_pid(simctl('launch', '--terminate-running-process', udid, bundle_id, env=environment))
print('UIKit fixture: launched actual UIKit scene', flush=True)
result_path = container / 'Documents/ui-lifecycle-result.json'
phase_path = container / 'Documents/ui-lifecycle-phase.json'
switched = False
deadline = time.monotonic() + 120
while time.monotonic() < deadline:
    if result_path.exists():
        result = json.loads(result_path.read_text())
        required = {
            'visible_non_key_overlay', 'inside_button_hit', 'outside_button_passthrough',
            'app_subview_cannot_cover_overlay', 'same_window_relayout', 'safe_area_relayout',
            'key_window_switch', 'single_visible_overlay', 'root_controller_replacement',
            'detached_presenter_recovers', 'nil_presenter_recovers', 'busy_key_window_switch_recovers',
            'unowned_modal_does_not_remove_button', 'picker_cancel_recovers',
            'loading_cancel_ignores_late_results', 'loading_failure_recovers',
            'loading_timeout_recovers', 'assignment_has_no_loading_deadline', 'assignment_cancel_recovers',
            'assignment_use_recovers', 'real_background_observed', 'real_resume_recovers',
            'host_nonce_present', 'owned_picker_hides_overlay', 'owned_assignment_hides_overlay',
            'loading_cancel_resets_busy', 'assignment_cancel_does_not_arm_pair', 'assignment_use_arms_pair',
        }
        checks = result.get('checks', [])
        names = {item.get('name') for item in checks if item.get('passed') is True}
        valid = (result.get('suite') == 'bereal493-real-uikit-lifecycle-v1'
                 and result.get('nonce') == nonce and result.get('passed') is True
                 and names == required and all(item.get('passed') is True for item in checks)
                 and switched)
        (output / 'ui-lifecycle-result.json').write_text(json.dumps(result, indent=2) + '\n')
        if not valid:
            print(json.dumps(result, indent=2), file=sys.stderr)
            raise SystemExit('UIKit lifecycle fixture failed or returned incomplete evidence')
        print('UIKit lifecycle fixture passed ' + str(len(checks)) + ' checks, including actual background/resume.')
        break
    if phase_path.exists():
        phase = json.loads(phase_path.read_text())
        if phase.get('nonce') != nonce:
            raise SystemExit('UIKit fixture phase nonce mismatch')
        if phase.get('phase') == 'waiting-background' and not switched:
            print('UIKit fixture: switching to Settings for real background/resume', flush=True)
            simctl('launch', udid, 'com.apple.Preferences')
            background_deadline = time.monotonic() + 15
            while time.monotonic() < background_deadline:
                current = json.loads(phase_path.read_text())
                if current.get('nonce') == nonce and current.get('phase') == 'backgrounded':
                    break
                if result_path.exists():
                    raise SystemExit('UIKit fixture failed while entering background')
                time.sleep(0.1)
            else:
                raise SystemExit('UIKit fixture did not observe actual scene background')
            switched = True
            # Keep the same process and the same production UI object alive.
            if launched_pid(simctl('launch', udid, bundle_id, env=environment)) != initial_pid:
                raise SystemExit('UIKit fixture process restarted instead of resuming')
    time.sleep(0.1)
else:
    raise SystemExit('UIKit lifecycle fixture timed out before a complete verdict')
PY
