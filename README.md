# BeReal 4.93.0 camera-roll adapter

The adapter replaces capture images with two user-selected camera-roll photos. R2 was signed, independently verified and handed off through owner-private HTTPS links. Current R3 addresses the photo-selection button disappearing or becoming inoperable. R3 signing and formal independent verification passed; its final-source UIKit CI and full HTTPS delivery verification passed; the Python suite has passed 109 tests. R3 real-device BeReal behavior and posting remain unverified.

## Current delivery status

R3 signed IPA is formally independently verified and complete HTTPS/landing verification passed. The [owner-private R3 download page](https://bereal493-apple-auth.a-yt.chatgpt.site/?v=382387cfe49e) is ready for final handoff; user download/device confirmation is absent. Signed source `91f13c2c783086a3a0c8f0997fe6e2e9c59657b0` passed UIKit gate `38763871232`/job `116521891001` on iOS Simulator SDK/runtime 18.5. Helper BeReal `0caf98fb29cd5be4da82ed2640d50e38f76d12c8` and Y3 `1ac5dd4da29c36cbce38c46ef58b0ded196d6b08` use the canonical signer/verifier from that source; signing run `38764019319` succeeded. Local Y3 checks passed 22 resign and 12 access-diagnostic tests (34 total). Final-source 91 UIKit CI passed 36/36 assertions/28 unique checks on iOS Simulator 18.5, including same-process restoration, pair/ImageIO and ARM64 checks. macOS ran 109 Python tests with one pre-existing OpenSSL-3 skip and no failures. Safe UI receipts: `ci-handoff/r3-ui-lifecycle-result.json`, `ci-handoff/r3-ui-artifact-verification.json`. R3 artifact `11988120311` contains the encrypted signed delivery; IPA is 140244155 bytes, SHA256 `382387cfe49eeec2b3af8954adc2b0ff8bc30181ab7db6fc5f19101467a511e4`. Independent 90-signature/five-profile/six-executable/auth-context checks passed, and signed dylib inspection found the new classes/label. Safe records: `ci-handoff/r3-signed-verification.json`, `ci-handoff/r3-signed-delivery-validation.json`, `ci-handoff/r3-adapter-ui-evidence.json`. Do not use R2 hashes or receipts as proof for R3.

R3 staging deployed to existing owner-private Site version 12 (source `3d4aa093df1920fda700c28488275169e710adcd`, deployment `appgdep_6ad0f89f2c348191837a6eb84ebaf853`) at `2026-10-15T16:03:45.474256Z`; owner policy, seven transferred parts and seven Site tests passed. Alias `BeReal493-CameraRoll-R3-SIGNED-382387cfe49e.ipa` is saved and rehashed. The complete live HTTPS/landing check passed: all 140244155 bytes/SHA256, attachment HEAD/filename, cross-part/unsatisfiable ranges and access/cache rejection checks. Safe proof is `ci-handoff/r3-https-delivery-verification.json`, 2214 bytes, SHA256 `e69029a9f5f315e73b15d533ee2a7a86b1bb61213e0cdc9eb9c8b8f973306544`. The R3 link is ready to send; link handoff and user receipt are not yet recorded.

The delivery acceptance condition is a verified signed IPA. Real-device installation and live posting are not required acceptance tests. Initial R1 installation, launch and image injection succeeded according to the user after external re-signing; R2 download/device confirmation and all R3 runtime improvements remain unconfirmed. No successful ordinary post has been reported.

## Previous R2 delivery

- File: `BeReal493-CameraRoll-R2-SIGNED-ca5d073c1bbd.ipa`, 140233684 bytes.
- SHA256: `ca5d073c1bbd2aaabff8ea6956b2ab85f344d51249912981cac9f89d97d2364b`.
- [Historical R2 handoff URL; Site now serves current R3](https://bereal493-apple-auth.a-yt.chatgpt.site/?v=ca5d073c1bbd); its links were presented in the prior final reply. Link handoff does not prove user download or device testing. The old URL is a historical record; current R2 file availability is not asserted.
- Source `8e4394e016639fd7e941148796ea0af38d1e8ad0`; signing CI `38525572234` succeeded. Independent validation passed 90 Mach-O CMS/page/special hashes, five exact profiles for the same registered device, executable modes and the patched auth factory. Complete HTTPS download matched the IPA hash.
- Safe receipts: `ci-handoff/r2-signed-verification.json`, `ci-handoff/r2-signed-delivery-validation.json` and `ci-handoff/r2-https-delivery-verification.json`.

The older unsigned package/build is historical. The project has progressed through actual signing and verified delivery; it is not limited to that unsigned prototype.

## Select photos

1. Open the app and use the floating `写真を選択` control.
2. Select exactly two images. Confirm the back/front previews and swap them if needed.
3. Choose `次の撮影に使う`, open BeReal's camera screen and use its normal shutter.
4. Inspect the resulting draft. Any submission uses the app's own controls; the adapter never posts automatically.
5. Long-press the floating control to cancel a prepared pair. A pair expires after three minutes and clears after both camera roles read their replacement data.

R3 keeps the control in a dedicated scene overlay and passes touches outside it through to the app. It refreshes layout/host changes, handles picker/assignment cancellation and loading/presentation deadlines, and restores the control after background transitions. These implementation properties passed the final-source UIKit harness; real-device BeReal validation remains unconfirmed, not a claim that the reported issue is empirically resolved.

## Integration and evidence

`CameraRollAdapter.m` intercepts public `AVCapturePhotoOutput` capture entry points and checks two delegate classes verified in the exact original: `CameraKitData.PhotoCaptureDelegate` and `Camera.CameraPhotoCaptureProcessor`. Callback ABI is checked at runtime. The actual camera position determines front/back assignment; unsupported paths keep native behavior.

Each capture snapshots the selected pair using the capture settings' unique ID. Replacement data is associated with the real AVCapturePhoto; its concrete `fileDataRepresentation` implementation returns that data only for tagged photos. The original app continues its capture/draft/upload processing. R2 adds inverse EXIF-5 pixel compensation only for the verified front processor, leaving rear-camera and separate CameraKit routes unchanged.

Packaging also applies an exact guarded eight-byte token-storage factory patch, omitting the unavailable original access group so the app uses its own permitted default keychain. No Security API interception or foreign keychain grant is used. The original service and other executable bytes remain intact apart from documented packaging changes. See `CAPTURE_CONTRACT.md` and the safe front-orientation/auth-keychain evidence in `ci-handoff/`.

The old `Tweak.m` picker-only prototype remains for provenance and is not the active adapter.

## Signing and privacy

Existing Y3POSClient assets were reused inside the authorized signing CI to sign nested code with matching scoped Ad Hoc profiles. Private keys and Apple credentials remain in CI. The plaintext original IPA, signed IPA and binary delivery parts are absent from the public source repository. Download delivery uses the existing owner-private Site; it is not a public app Release.

Original input: BeReal 4.93.0 build 23026, `AlexisBarreyat.BeReal`, minimum iOS 17.0, SHA256 `e7d77665740c61f2b0d6eae21cb6052acd2add364db3f6b5fc9ef9198ac31cbc`. Initial adapter/input provenance `1f749cd1b2433d2a32694d5c91849d22f84f429f` and the complete encrypted v3 input remain recoverable as documented in `HANDOFF_CODEX.md`; older local paths are not assumed to exist.

## Reproduce and verification boundary

```sh
python3 -m unittest discover -s tests -v
# macOS CI compiles the adapter and runs native tests.
# This command creates an unsigned intermediate, not a signed deliverable:
python3 scripts/package_ipa.py original.ipa CameraRollAdapter.dylib BeReal493-CameraRoll-UNSIGNED.ipa
```

Source/native checks, actual signing, independent signature/profile checks and complete HTTPS hash verification are distinct stages. R2 passed these stages and its links were handed off. R3 currently has 109 passing Python tests and passing signing/formal independent checks; final-source UIKit CI and complete HTTPS verification passed; the link is ready for handoff. Draft appearance, runtime button recovery, orientation, login persistence, upload acceptance, notification/widget behavior and live posting must not be inferred from static or signing checks.
