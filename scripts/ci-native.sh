#!/bin/bash
set -euo pipefail
umask 077
[[ "$(uname -s)" == Darwin ]] || { echo 'macOS is required' >&2; exit 1; }
mkdir -p output
xcodebuild -version
xcrun --sdk macosx clang -fobjc-arc -framework Foundation BRPairState.m tests/pair_state.m -o "$RUNNER_TEMP/bereal493-pair-tests"
"$RUNNER_TEMP/bereal493-pair-tests"
xcrun --sdk macosx clang -fobjc-arc -framework Foundation -framework CoreGraphics -framework ImageIO \
  tests/front_orientation.m -o "$RUNNER_TEMP/bereal493-orientation-tests"
"$RUNNER_TEMP/bereal493-orientation-tests"
sdk_path="$(xcrun --sdk iphoneos --show-sdk-path)"
xcrun --sdk iphoneos clang -dynamiclib -arch arm64 -isysroot "$sdk_path" \
  -miphoneos-version-min=17.0 -fobjc-arc -fmodules -O2 \
  -framework UIKit -framework PhotosUI -framework AVFoundation -framework CoreGraphics \
  -install_name '@executable_path/Frameworks/CameraRollAdapter.dylib' \
  CameraRollAdapter.m BRPairState.m -o output/CameraRollAdapter.dylib
temporary_directory="$(mktemp -d "$RUNNER_TEMP/bereal493.XXXXXX")"
trap 'rm -rf "$temporary_directory"' EXIT
export BR_TEMP_DIRECTORY="$temporary_directory"
python3 - <<'PY'
import hashlib, json, os, pathlib, urllib.request, zipfile
event = json.loads(pathlib.Path(os.environ['GITHUB_EVENT_PATH']).read_text())
url = event.get('inputs', {}).get('source_ipa_url', '')
if not url:
    print('No IPA transfer requested; source-only native compilation completed.')
    raise SystemExit(0)
if not url.startswith('https://') or any(c in url for c in '\r\n'):
    raise SystemExit('A single HTTPS source URL is required')
print('::add-mask::' + url)
root = pathlib.Path(os.environ['BR_TEMP_DIRECTORY'])
ipa = root / 'source.ipa'
with urllib.request.urlopen(url, timeout=120) as source, ipa.open('wb') as target:
    while chunk := source.read(1024 * 1024):
        target.write(chunk)
with ipa.open('rb') as stream:
    digest = hashlib.file_digest(stream, 'sha256').hexdigest()
if digest != 'e7d77665740c61f2b0d6eae21cb6052acd2add364db3f6b5fc9ef9198ac31cbc':
    raise SystemExit('Input IPA hash does not match the supplied original')
with zipfile.ZipFile(ipa) as archive:
    for item in archive.infolist():
        name = pathlib.PurePosixPath(item.filename)
        if name.is_absolute() or '..' in name.parts:
            raise SystemExit('Invalid archive path')
    archive.extractall(root / 'app')
PY
if [[ ! -f "$temporary_directory/source.ipa" ]]; then
  shasum -a 256 output/CameraRollAdapter.dylib > output/SHA256SUMS
  exit 0
fi
python3 scripts/inspect_ipa.py "$temporary_directory/source.ipa" > output/input-verification.json
app_path="$temporary_directory/app/Payload/BeReal.app"
xcrun otool -ov "$app_path/BeReal" | gzip > output/main-objc.txt.gz
xcrun nm -m "$app_path/BeReal" | gzip > output/main-symbols.txt.gz
for framework_name in Entities Camera; do
  framework_binary="$app_path/Frameworks/$framework_name.framework/$framework_name"
  if [[ -f "$framework_binary" ]]; then
    xcrun nm -m "$framework_binary" | gzip > "output/$framework_name-symbols.txt.gz"
    xcrun otool -ov "$framework_binary" | gzip > "output/$framework_name-objc.txt.gz"
  fi
done
shasum -a 256 output/CameraRollAdapter.dylib > output/SHA256SUMS
echo 'Native library built. Posting adapter and installable IPA remain incomplete.'
