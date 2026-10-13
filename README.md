# BeReal 4.93.0 Camera Roll prototype | v3

**Current status: nonfunctional for posting.** This repository builds an experimental photo-picker library, NOT an installable IPA. No private BeReal posting APIs have been validated or called.

## Current execution status (2026-10-13)

- Public repository: `444yttt/BeReal493`, authorized by the user.
- Native ARM64 dylib compiled successfully with Xcode 16.4 (16F6) on macOS 15.
- Build commit: `1da4ccca3752afe777304d784b868ae58417a74d`.
- Successful build: https://github.com/444yttt/BeReal493/actions/runs/38405245770
- All four Python tests passed. The build used public source only and did not transfer the original IPA.
- User acceptance scope is IPA delivery only; live device posting is not required for this delivery.
- IPA transfer to GitHub Actions remains blocked pending explicit authorization after automatic approval review rejected disclosure of its temporary access URL.
- No posting adapter, modified IPA, or signed IPA exists yet.

## Validated against supplied IPA

- Identifier `AlexisBarreyat.BeReal`
- App version `4.93.0` / build `23026`
- Minimum iOS `17.0`
- ARM64 Mach-O main binary, 77,690,240 bytes
- SHA-256: `e7d77665740c61f2b0d6eae21cb6052acd2add364db3f6b5fc9ef9198ac31cbc`
- The input IPA is **not** committed or included in this archive.

## Changes from v2

- Two-photo picker retains user selection order despite asynchronous loading.
- Posts `BRPrototypeTwoPhotosReady` in-process notification with `front` / `back` UIImage objects once *both* images load. Names are provisional, and orientation mapping is not verified.
- Adds offline IPA metadata validation (`python3 scripts/inspect_ipa.py path/to/file.ipa`) with explicit bundle and version checks.
- Adds unit tests and CI test step. Two unit tests passed locally.

## Local verification

```sh
python3 -m unittest discover -s tests -v
python3 scripts/inspect_ipa.py /path/to/BeReal_4.93.0.ipa
```

## Remaining blockers

1. Correctly identify BeReal 4.93.0's private capture-to-draft data contract and callback threading. Static string references are **not** sufficient evidence for a safe function hook.
2. Write/validate a separately gated adapter and test in an authorized development environment; do not upload photos or call unknown endpoints to infer behavior.
3. Native compilation is now verified using Xcode directly. Theos is unnecessary for the current picker-only source.
4. Inject the resulting library, correctly re-sign the complete modified app (including nested code), and test on iPhone. **No signed IPA was produced**.

Past first-party signing patterns inspected: `444yttt/Y3POSClient` and `444yttt/FORM`. Their signing secrets are not shared with this project. A modified third-party app is not equivalent to a first-party TestFlight upload.
