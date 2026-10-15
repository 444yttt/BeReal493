# Static capture contract: verified original 4.93.0

Source SHA256: `e7d77665740c61f2b0d6eae21cb6052acd2add364db3f6b5fc9ef9198ac31cbc`.
Executable: ARM64 `Payload/BeReal.app/BeReal`, image base `0x100000000`.
Encryption command: cryptid `0`.

## Objective-C callback metadata

| Class | Relative method list | Callback IMP | Encoding |
| --- | --- | --- | --- |
| `_TtC13CameraKitData20PhotoCaptureDelegate` | `0x1031db0c8` | `0x101f94fdc` | `v40@0:8@16@24@32` |
| `_TtC6Camera27CameraPhotoCaptureProcessor` | `0x1031de8d0` | `0x102271350` | `v40@0:8@16@24@32` |

Both callback selectors resolve through selector reference `0x1041135a8` to `0x103a2706a`, containing `captureOutput:didFinishProcessingPhoto:error:`. Both also expose `captureOutput:didFinishCaptureForResolvedSettings:error:` with the same Objective-C type encoding.

## Concrete image-data call sites

The `fileDataRepresentation` string is at `0x103a342e5`. Selector reference `0x1040eea48` resolves to it. ARM64 ADRP/LDR pairs load this selector into register x1 at these callback-body locations:

| Callback IMP | Swift body loaded into x5 by thunk | Selector load | Following call |
| --- | --- | --- | --- |
| `0x101f94fdc` | `0x101f95dc4` | `0x101f95f94` / `0x101f95f98` | BL at `0x101f95fa0` to `0x10315a294` |
| `0x102271350` | `0x1022724a4` | `0x1022725cc` / `0x1022725d0` | BL at `0x1022725d8` to `0x10315a294` |

These findings establish real method metadata and image-data read call sites. They do not establish successful on-device substitution, draft appearance, upload, or server acceptance. The implementation uses runtime class/selector lookup and checked Objective-C ABI; it does not execute these absolute addresses.

## Packaging evidence

Original load-command table ends at file offset `19896`; the first text payload starts at `32768`, leaving `12872` bytes of header padding. The packager first applies only the eight instruction bytes described below, then removes LC_CODE_SIGNATURE, adds one LC_LOAD_DYLIB pointing to `@executable_path/Frameworks/CameraRollAdapter.dylib`, checks padding, and preserves all other payload bytes and offsets.

## Front-camera orientation correction

The original IPA is SHA256-pinned to `e7d77665740c61f2b0d6eae21cb6052acd2add364db3f6b5fc9ef9198ac31cbc`. All positions below are relative executable offsets, not runtime addresses.

`Camera.CameraPhotoCaptureProcessor` reads `fileDataRepresentation` at `0x22725d8`, bridges it to Foundation Data, constructs `UIImage` with `initWithData:` at `0x2272640`, and calls the image-processing helper `0x22711e8` from `0x227267c`.

That helper's camera-role boolean is independently identified by the adjacent telemetry helper `0x22710a4`: zero produces the string `front`, and one produces `back`. Both paths load the same field referenced by `0x42f56f8`.

The zero/front branch gets the decoded image's `CGImage` and constructs another `UIImage` with `initWithCGImage:scale:orientation:`. Scale is 1. The instruction at `0x22712a4` sets the orientation argument to **6**, `UIImageOrientationLeftMirrored`, equivalent to **EXIF orientation 5**. The back branch skips this forced orientation. The observed path does not read `AVCapturePhoto.metadata` to select that orientation, so changing only the photo's metadata to Up cannot correct this path.

The crop helper `0x22680f4` preserves this transformation. If no resize is needed, it returns the same UIImage with orientation 6. Otherwise, helper `0xff65b0` calls `UIGraphicsBeginImageContext`, the UIImage's `drawInRect:` at `0xff6680`, and `UIGraphicsGetImageFromCurrentImageContext`. UIKit drawing applies image orientation, so the resize branch renders the orientation into pixels.

The separate `CameraKitData.PhotoCaptureDelegate` callback `0x1f95dc4` bridges the replacement data and yields an AsyncStream event at `0x1f96004`. Its callback body contains no UIImage/CGImage orientation transformation or photo-metadata orientation read. Every downstream AsyncStream consumer has not been fully symbolicated; this evidence supports leaving that route unchanged rather than applying the processor-specific correction globally.

The minimum correction is an inverse pixel transform only for a physical front-camera replacement sent to the two exact names of `CameraPhotoCaptureProcessor`. EXIF-5 transpose is self-inverse, so pre-transposing upright pixels compensates for the app's explicit orientation-6 construction. The encoded JPEG should remain orientation Up, with swapped raw dimensions. A non-square image with four distinct corner colors and an independent macOS ImageIO EXIF-5 rendering oracle can test the round trip. This is not an empirical on-device validation.

This record contains no raw crash report, runtime address, device or user identifier, UUID, certificate subject or access URL.

## Authentication token storage after signing

`CoreAuthenticationData.KeychainTokenStorage` read, write and clear paths share the factory at relative/file offset `0x26d2754`. The original factory passes the original App Group as an explicit `KeychainAccess.Keychain` accessGroup, which the scoped Ad Hoc profiles do not grant. The initializer stores its optional Swift String from x2/x3; the query builder at `0x8d0614` skips `kSecAttrAccessGroup` when the high word is zero. The existing service-only initializer independently stores both words as zero at `0x8cebc8`.

The exact original main is SHA256 `d64203bfef02feb41680a43224762e8e5be2f9723e6f62924d8d5bfc2d1b2cd6`. Two four-byte instructions at `0x26d2784` and `0x26d2790` become `mov x2, #0` and `mov x3, #0`. This selects the app's permitted default keychain group. The service, initializer call and every other original byte remain intact. There is no Security API interception or grant to another app's items.

The patcher requires the full original main SHA256, ARM64 executable identity, a single cryptid-zero command, both original argument writers and the complete 80-byte factory context. It rejects foreign, tampered, partial and repeated input. Packaging and independent signed-delivery verification require the exact patched context and both replacement instructions. Safe proof is in `ci-handoff/auth-keychain-evidence.json`. Device login persistence and live posting remain unverified.

## R3 photo-selection control lifecycle (signed/UIKit verified, device pending)

R3 addresses the reported disappearing or inoperable photo-selection control. This UI contract is separate from the original capture ABI, front-orientation evidence and exact token-storage factory patch above; those input/provenance boundaries remain unchanged.

The implementation uses a dedicated scene overlay without making it the key window. Hit testing passes touches outside the photo-selection button through to the underlying app. Notification refresh and a 0.5-second timer in common run-loop modes update the safe area, layout and host changes; background/foreground handling restores the control. This avoids relying solely on an earlier app view retaining the button.

Busy state covers both the photo picker and front/back assignment. Cancellation and bounded loading/presentation flows restore interactivity: loading has a 45-second deadline, presentation has a 3-second deadline, and generation/deadline checks reject late callbacks from abandoned flows. These describe the intended current implementation, not empirical proof of recovery on an iPhone.

The Python suite passed 109 tests. Signed build source `91f13c2c783086a3a0c8f0997fe6e2e9c59657b0` / UIKit gate `38763871232`/job `116521891001` passed on SDK/runtime 18.5. Canonical signer/verifier helpers are published at BeReal `0caf98fb29cd5be4da82ed2640d50e38f76d12c8`; Y3 `1ac5dd4da29c36cbce38c46ef58b0ded196d6b08` signing run `38764019319` succeeded. Local Y3 checks passed 22 resign plus 12 access diagnostics (34 total). Final-source 91 UIKit gate passed 36/36 assertions/28 unique checks on SDK/runtime 18.5, including same-PID restoration, pair/ImageIO and ARM64 checks. macOS Python ran 109 tests with one pre-existing OpenSSL-3 skip and no failures. UI artifact `11987261910` is a 33322-byte ZIP, SHA256 `90d8c99a7a7c410834f4cd6b4008db63a1ec6a20d6bc8ee04b824369265feef8`; result SHA256 `dd6f5397879950cf5f90a9148e1d2697417f2e52be1f3b0197c98080242baa8b`, safe copies `ci-handoff/r3-ui-lifecycle-result.json` and `ci-handoff/r3-ui-artifact-verification.json`. Formal signed-delivery verification passed 90 Mach-O/five-profile/six-executable/auth-context checks. Signed-dylib inspection confirms the new UI classes and label in the actual IPA; safe evidence is `ci-handoff/r3-adapter-ui-evidence.json`. Binary/signature evidence and the passing controlled UIKit harness are separate. Neither establishes real-device behavior inside BeReal. Complete HTTPS/landing verification passed separately (`ci-handoff/r3-https-delivery-verification.json`); device control recovery inside BeReal and ordinary posting remain unverified.
