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
