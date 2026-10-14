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

Original load-command table ends at file offset `19896`; the first text payload starts at `32768`, leaving `12872` bytes of header padding. The packager removes LC_CODE_SIGNATURE, adds one LC_LOAD_DYLIB pointing to `@executable_path/Frameworks/CameraRollAdapter.dylib`, checks padding, and verifies that all bytes from the first payload offset onward remain unchanged.

## Front-camera orientation correction

The original IPA is SHA256-pinned to `e7d77665740c61f2b0d6eae21cb6052acd2add364db3f6b5fc9ef9198ac31cbc`. All positions below are relative executable offsets, not runtime addresses.

`Camera.CameraPhotoCaptureProcessor` reads `fileDataRepresentation` at `0x22725d8`, bridges it to Foundation Data, constructs `UIImage` with `initWithData:` at `0x2272640`, and calls the image-processing helper `0x22711e8` from `0x227267c`.

That helper's camera-role boolean is independently identified by the adjacent telemetry helper `0x22710a4`: zero produces the string `front`, and one produces `back`. Both paths load the same field referenced by `0x42f56f8`.

The zero/front branch gets the decoded image's `CGImage` and constructs another `UIImage` with `initWithCGImage:scale:orientation:`. Scale is 1. The instruction at `0x22712a4` sets the orientation argument to **6**, `UIImageOrientationLeftMirrored`, equivalent to **EXIF orientation 5**. The back branch skips this forced orientation. The observed path does not read `AVCapturePhoto.metadata` to select that orientation, so changing only the photo's metadata to Up cannot correct this path.

The crop helper `0x22680f4` preserves this transformation. If no resize is needed, it returns the same UIImage with orientation 6. Otherwise, helper `0xff65b0` calls `UIGraphicsBeginImageContext`, the UIImage's `drawInRect:` at `0xff6680`, and `UIGraphicsGetImageFromCurrentImageContext`. UIKit drawing applies image orientation, so the resize branch renders the orientation into pixels.

The separate `CameraKitData.PhotoCaptureDelegate` callback `0x1f95dc4` bridges the replacement data and yields an AsyncStream event at `0x1f96004`. Its callback body contains no UIImage/CGImage orientation transformation or photo-metadata orientation read. Every downstream AsyncStream consumer has not been fully symbolicated; this evidence supports leaving that route unchanged rather than applying the processor-specific correction globally.

The minimum correction is an inverse pixel transform only for a physical front-camera replacement sent to the two exact names of `CameraPhotoCaptureProcessor`. EXIF-5 transpose is self-inverse, so pre-transposing upright pixels compensates for the app's explicit orientation-6 construction. The encoded JPEG should remain orientation Up, with swapped raw dimensions. A non-square image with four distinct corner colors and an independent macOS ImageIO EXIF-5 rendering oracle can test the round trip. This is not an empirical on-device validation.

This record contains no raw crash report, runtime address, device or user identifier, UUID, certificate subject or access URL.
