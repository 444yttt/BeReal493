# BeReal 4.93.0 camera-roll adapter

The adapter replaces capture images with two user-selected camera-roll photos. Current R4 repairs native post-allowance storage for the re-signed app, addressing the reported missing additional-post plus control. R4 is signed, formally independently verified and fully verified over owner-private HTTPS. [Download R4](https://bereal493-apple-auth.a-yt.chatgpt.site/?v=c1759fc9853f). Real-device behavior remains unverified.

## Current delivery status

R4 source `0e1f94e1f7bbf5bf05d5fe1f1197d382acdc1a6b` is signed and formal independent verification passed. The IPA is 140244174 bytes, SHA256 `c1759fc9853fcbe724a9041c4101affce99848d21c9302bbd79adba0532cb589`. The existing owner-private Site now serves R4, and complete HTTPS verification matched every byte and the signed hash. [The verified download page](https://bereal493-apple-auth.a-yt.chatgpt.site/?v=c1759fc9853f) is prepared for the final reply; user download and device behavior remain unconfirmed.

Source CI `46022786258`/job `140586404788` passed 36 UIKit assertions/28 unique checks; it ran 124 Python tests with two skips. The root-local run with the exact original passed all 124 without skips. Canonical helper pins are at `2b767399e6f3734fd87791f35efe7a79471ff5f4`; Y3 `edf4c69f1e405aca77921f62a26d920b8b7f50d7`, signing run `46023681789`/job `140589477308`, produced recipient-encrypted artifact `15211570699`. Formal checks passed 90 Mach-O files/slices, five exact profiles for the same one device, six executable modes, primary certificate and both keychain factory contexts. Independent actual signed-byte checks also verified 40 native ranges and the complete 51634628-byte native text section, with only the four authorized auth/post argument writers changed; see [the final native-byte evidence](ci-handoff/r4-native-final-bytes.json).

The exact BeReal 4.93.0/build 23026 original was recovered and hash-verified. Static analysis traced the server-provided remaining-post count into a native keychain wrapper whose separate singleton still requested the original developer's unavailable group. Read errors return its default 0, and native eligibility controls the extra card's plus glyph and enabled state. R4 changes only the singleton's two explicit group arguments, allowing the app's own permitted keychain to retain the native allowance. The same singleton also stores the stable device ID. Native server quotas, timing checks and UI gates remain in use. See [the storage dataflow](ci-handoff/post-storage-dataflow.md) and [verification evidence](ci-handoff/post-storage-evidence.json).

Site version 13 deployed successfully at `2026-11-27T15:29:37.681275+00:00`. The full download, landing filename/hash, attachment length/cache/no-sniff headers, 206/416 ranges and HEAD behavior passed. Access remains limited to one owner; R4 unauthorized, invalid-token, forged-identity and cache-negative checks returned 401. Safe delivery proofs are `ci-handoff/r4-site-publication.json` and `ci-handoff/r4-https-delivery-verification.json`. The proof's false link-sent flag records its pre-reply timestamp; it does not indicate a failed download check.

The repair has not been confirmed on the user's device and does not guarantee a server-granted additional post. Missing APNs/original App Group rights remain separate limitations; this change does not restore push or widgets. Delivery acceptance is a verified signed IPA; installation and live posting are not required acceptance tests.

## Previous R3 delivery

R3 signed IPA is formally independently verified and complete HTTPS/landing verification passed. The [historical R3 download page; Site now serves R4](https://bereal493-apple-auth.a-yt.chatgpt.site/?v=382387cfe49e) was handed off; user download/device confirmation is absent. Signed source `91f13c2c783086a3a0c8f0997fe6e2e9c59657b0` passed UIKit gate `38763871232`/job `116521891001` on iOS Simulator SDK/runtime 18.5. Helper BeReal `0caf98fb29cd5be4da82ed2640d50e38f76d12c8` and Y3 `1ac5dd4da29c36cbce38c46ef58b0ded196d6b08` use the canonical signer/verifier from that source; signing run `38764019319` succeeded. Local Y3 checks passed 22 resign and 12 access-diagnostic tests (34 total). Final-source 91 UIKit CI passed 36/36 assertions/28 unique checks on iOS Simulator 18.5, including same-process restoration, pair/ImageIO and ARM64 checks. macOS ran 109 Python tests with one pre-existing OpenSSL-3 skip and no failures. Safe UI receipts: `ci-handoff/r3-ui-lifecycle-result.json`, `ci-handoff/r3-ui-artifact-verification.json`. R3 artifact `11988120311` contains the encrypted signed delivery; IPA is 140244155 bytes, SHA256 `382387cfe49eeec2b3af8954adc2b0ff8bc30181ab7db6fc5f19101467a511e4`. Independent 90-signature/five-profile/six-executable/auth-context checks passed, and signed dylib inspection found the new classes/label. Safe records: `ci-handoff/r3-signed-verification.json`, `ci-handoff/r3-signed-delivery-validation.json`, `ci-handoff/r3-adapter-ui-evidence.json`. Do not use R2 hashes or receipts as proof for R3.

R3 staging deployed to existing owner-private Site version 12 (source `3d4aa093df1920fda700c28488275169e710adcd`, deployment `appgdep_6ad0f89f2c348191837a6eb84ebaf853`) at `2026-10-15T16:03:45.474256Z`; owner policy, seven transferred parts and seven Site tests passed. Alias `BeReal493-CameraRoll-R3-SIGNED-382387cfe49e.ipa` is saved and rehashed. The complete live HTTPS/landing check passed: all 140244155 bytes/SHA256, attachment HEAD/filename, cross-part/unsatisfiable ranges and access/cache rejection checks. Safe proof is `ci-handoff/r3-https-delivery-verification.json`, 2214 bytes, SHA256 `e69029a9f5f315e73b15d533ee2a7a86b1bb61213e0cdc9eb9c8b8f973306544`. The R3 link was handed off in the prior final reply; older false flags are historical pre-handoff snapshots, and user download/device confirmation remains absent.

The delivery acceptance condition is a verified signed IPA. Real-device installation and live posting are not required acceptance tests. Initial R1 installation, launch and image injection succeeded according to the user after external re-signing; R2 download/device confirmation and all R3 runtime improvements remain unconfirmed. The current first-post report is user evidence; its installed revision/signature and repaired additional-post behavior have not been independently verified.

## Previous R2 delivery

- File: `BeReal493-CameraRoll-R2-SIGNED-ca5d073c1bbd.ipa`, 140233684 bytes.
- SHA256: `ca5d073c1bbd2aaabff8ea6956b2ab85f344d51249912981cac9f89d97d2364b`.
- [Historical R2 handoff URL; Site now serves R4](https://bereal493-apple-auth.a-yt.chatgpt.site/?v=ca5d073c1bbd); its links were presented in the prior final reply. Link handoff does not prove user download or device testing. The old URL is a historical record; current R2 file availability is not asserted.
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

Packaging applies the existing exact guarded eight-byte token-storage factory patch, followed by R4's separate exact guarded eight-byte LocalStorage factory patch. Both omit unavailable original access groups so the app uses its own permitted default keychain. The R4 patch requires the exact output of the auth patch and verifies the entire 124-byte native factory; packaging, signing receipts and independent verification require both patches. No Security API interception or foreign keychain grant is used. The original service and other executable bytes remain intact apart from documented packaging changes. See `CAPTURE_CONTRACT.md` and the safe front-orientation/auth-keychain evidence in `ci-handoff/`.

The old `Tweak.m` picker-only prototype remains for provenance and is not the active adapter.

## Signing and privacy

Existing Y3POSClient assets were reused inside the authorized signing CI to sign nested code with matching scoped Ad Hoc profiles. Private keys and Apple credentials remain in CI. The plaintext original IPA, signed IPA and binary delivery parts are absent from the public source repository. Download delivery uses the existing owner-private Site; it is not a public app Release.

Original input: BeReal 4.93.0 build 23026, `AlexisBarreyat.BeReal`, minimum iOS 17.0, SHA256 `e7d77665740c61f2b0d6eae21cb6052acd2add364db3f6b5fc9ef9198ac31cbc`. The exact original has been recovered for R4. Initial adapter/input provenance `1f749cd1b2433d2a32694d5c91849d22f84f429f` and historical encrypted recovery records are documented in `HANDOFF_CODEX.md`; expired artifacts and older local paths are not assumed available.

## Reproduce and verification boundary

```sh
python3 -m unittest discover -s tests -v
# macOS CI compiles the adapter and runs native tests.
# This command creates an unsigned intermediate, not a signed deliverable:
python3 scripts/package_ipa.py original.ipa CameraRollAdapter.dylib BeReal493-CameraRoll-UNSIGNED.ipa
```

Source/native checks, actual signing, independent signature/profile checks and complete HTTPS hash verification are distinct stages. R2 passed these stages and its links were handed off. R3 passed signing, independent checks, final-source UIKit CI and complete HTTPS verification, and its link was handed off. Current R4 has 124 passing local Python tests, passing source/native CI, a signed IPA and formal independent signed-file checks. Owner-private HTTPS publication and complete download verification passed; the verified R4 page is prepared for the final reply. Draft appearance, runtime button recovery, orientation, login persistence, upload acceptance, notification/widget behavior and live posting must not be inferred from static or signing checks.
