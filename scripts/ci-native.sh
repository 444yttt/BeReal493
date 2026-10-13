#!/bin/bash
set -euo pipefail
umask 077
[[ "$(uname -s)" == Darwin ]] || { echo 'macOS is required' >&2; exit 1; }
mkdir -p output
xcodebuild -version
sdk_path="$(xcrun --sdk iphoneos --show-sdk-path)"
xcrun --sdk iphoneos clang -dynamiclib -arch arm64 -isysroot "$sdk_path" \
  -miphoneos-version-min=17.0 -fobjc-arc -fmodules -O2 \
  -framework UIKit -framework PhotosUI -framework UniformTypeIdentifiers \
  -install_name '@executable_path/Frameworks/CameraRollPrototype.dylib' \
  Tweak.m -o output/CameraRollPrototype.dylib
temporary_directory="$(mktemp -d "$RUNNER_TEMP/bereal493.XXXXXX")"
trap 'rm -rf "$temporary_directory"' EXIT
export BR_TEMP_DIRECTORY="$temporary_directory"
python3 - <<'PY'
import hashlib, os, pathlib, urllib.request, zipfile
url = os.environ['SOURCE_IPA_URL']
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
shasum -a 256 output/CameraRollPrototype.dylib > output/SHA256SUMS
echo 'Native library built. Posting adapter and installable IPA remain incomplete.'
