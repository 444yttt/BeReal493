# Verified execution status (2026-10-13)

- User authorized public repository `444yttt/BeReal493`, IPA-only delivery, and transfer of the original IPA/access URL to GitHub Actions.
- Original input recovered; SHA256 `e7d77665740c61f2b0d6eae21cb6052acd2add364db3f6b5fc9ef9198ac31cbc` matched. Identity `AlexisBarreyat.BeReal`, version `4.93.0`, build `23026`, iOS 17.0, ARM64.
- Original main executable has cryptid=0. Concrete callback metadata and image-data-read sites verified; see CAPTURE_CONTRACT.md.
- `CameraRollAdapter.m` and `BRPairState.m` implement a version-guarded Objective-C photo adapter, explicit front/back assignment, capture snapshots by uniqueID, normalized JPEG replacement, expiry, and automatic pair reset.
- Native adapter compiled with Xcode 16.4 (16F6); Foundation pair-state tests passed in Actions run `38407306722`, build commit `945cd4bc230d6205d34923c0bcf82fa2d4f1cb45`.
- Eight local Python tests passed, including Mach-O packaging failure/preservation checks.
- Generated `BeReal493-CameraRoll-UNSIGNED.ipa`; SHA256 `66dbd05ea861c6213e8b795aa8e446b1d84eeceb30dc336742c7591471f5d4ef`.
- IPA ZIP CRCs, unique adapter dependency, removal of the invalid root signature command, and unchanged executable payload bytes verified.
- No device signing/provisioning, installation, launch, draft verification, or live posting test was performed. IPA is unsigned and requires full nested-code re-signing for a non-jailbroken iPhone.
- Existing Y3POSClient/FORM signing secrets were not accessed or reused. Their App Store profiles are not directly installable provisioning for this modified app.

## Continuation

Use the signed-IPA delivery method explicitly chosen by the user. Obtain or prepare matching device provisioning and an authorized certificate through a secure path, re-sign every nested executable, validate all signatures/entitlements, and then generate a new signed IPA. Do not call the present unsigned package installable or device-tested.
