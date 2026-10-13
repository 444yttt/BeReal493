# BeReal 4.93.0 camera-roll adapter

The adapter is implemented and compiled, and an unsigned IPA has been generated. Device launch and posting have not been tested. This is not a claim of successful installation or posting.

## Deliverable

- `BeReal493-CameraRoll-UNSIGNED.ipa`
- SHA256: `66dbd05ea861c6213e8b795aa8e446b1d84eeceb30dc336742c7591471f5d4ef`
- Source IPA: BeReal 4.93.0 build 23026, `AlexisBarreyat.BeReal`, minimum iOS 17.0.
- Original SHA256: `e7d77665740c61f2b0d6eae21cb6052acd2add364db3f6b5fc9ef9198ac31cbc`.
- Native adapter build commit: `945cd4bc230d6205d34923c0bcf82fa2d4f1cb45`.
- Successful native build: https://github.com/444yttt/BeReal493/actions/runs/38407306722
- Xcode 16.4 (16F6), ARM64/iOS 17, public UIKit/PhotosUI/AVFoundation and Objective-C runtime.

## Use after device signing

1. Open the app and choose `写真を選択`.
2. Select exactly two images. Confirm the back/front previews; swap them if needed.
3. Tap `次の撮影に使う`, open BeReal's camera screen, and use its normal shutter.
4. Inspect the resulting draft and submit with the app's own controls.
5. Long-press the floating button to cancel a prepared pair. A pair expires after three minutes and is cleared once both camera roles have read their replacement data.

The adapter does not submit posts automatically. It normalizes UIImage orientation and encodes JPEG data with a longest edge of 2048 pixels. The app continues its original capture processing; draft behavior, crop, upload acceptance, and visual front/back placement still need device verification.

## Integration

`CameraRollAdapter.m` intercepts the public `AVCapturePhotoOutput` capture entry and checks the delegate class. It modifies only two classes verified in this exact binary: `CameraKitData.PhotoCaptureDelegate` and `Camera.CameraPhotoCaptureProcessor`. Callback ABI is checked at runtime before installation. The actual camera device position determines front/back assignment; unknown paths keep native behavior and show an unsupported status.

Each capture snapshots the selected pair using the capture settings' unique ID. The adapter associates replacement data with the real AVCapturePhoto and hooks its concrete class's `fileDataRepresentation`. Untagged photos call the original implementation. No private Swift ABI, upload endpoint, login API, or hardcoded function offset is invoked. Static binary evidence is documented in `CAPTURE_CONTRACT.md`.

The old `Tweak.m` picker prototype is retained for provenance and is not included in the new adapter build.

## Signing boundary

The generated IPA is **unsigned**. It cannot be installed directly on an ordinary iPhone. A sideloading signer must sign every nested executable/library and provide matching device provisioning. App Store distribution profiles used by Y3POSClient are not direct-install profiles for this app. Existing Y3POSClient/FORM keys have not been read, copied, or reused.

`package_ipa.py` removes the invalid root code-signature load command, app signature resources, and embedded profiles. It appends a load command for the compiled adapter without moving payload offsets. Remaining original nested Mach-O signatures must be replaced by the downstream signer.

## Reproduce

```sh
python3 -m unittest discover -s tests -v
# On a macOS runner, scripts/ci-native.sh compiles the adapter and runs Foundation pair-state tests.
python3 scripts/package_ipa.py original.ipa CameraRollAdapter.dylib BeReal493-CameraRoll-UNSIGNED.ipa
```

The original third-party IPA is not stored in the public source repository. Source-only Actions builds require no original IPA. An optional, explicitly authorized temporary IPA URL can be supplied to workflow_dispatch for offline analysis.

## Verification completed

- Original input hash and exact app identity/build checked.
- Objective-C callback names, type encodings, and image-data read call sites checked in the supplied executable.
- Foundation pair-state tests run on macOS: front-first completion, duplicate-role handling, stale-pair protection, expiry, invalid role, empty data.
- Eight Python tests passed locally, including Mach-O offset preservation, duplicate injection rejection, encrypted-image rejection, insufficient/nonempty header-padding rejection.
- Real IPA packaging checked its unique dylib dependency, absence of a root signature command, preservation of executable payload bytes, and ZIP CRCs.

## Not verified

Device signing, installation, launch, image substitution on a real device, BeReal draft appearance, and posting success. The user requested IPA delivery without device/live-post acceptance testing.
