# Agent execution contract: BeReal 4.93.0 camera-roll posting

## Current user overrides (2026-10-13)
- User authorizes the public repository `444yttt/BeReal493`.
- The requested delivery is the IPA only; installation and live test posting are not acceptance requirements for this delivery.
- Continue to report whether the posting adapter is implemented and whether the IPA is signed. Do not call a picker-only prototype a working posting modification.
- The original third-party IPA is temporary build input, not repository source.

## Outcome
Deliver a **working, user-installable iOS IPA** based on the **user-supplied BeReal 4.93.0** that allows selecting two user-selected camera-roll photos and creating an ordinary BeReal post on a **non-jailbroken iPhone**. Do not claim success until it was installed and an explicitly authorized test post succeeded. Never misrepresent prototype operation as successful posting.

## Inputs already available in originating ChatGPT conversation
- Uploaded IPA: `AlexisBarreyat.BeReal_4.93.0_und3fined.ipa`, SHA256 `e7d77665740c61f2b0d6eae21cb6052acd2add364db3f6b5fc9ef9198ac31cbc`. **User must reattach this original IPA in any new Work session if its bytes are not accessible; do not fetch untrusted replacements.**
- Existing research and partial implementation: Tweak.m, Makefile, scripts, tests in this package.
- GitHub user repository precedents: `444yttt/Y3POSClient` (build-ipa and signing), `444yttt/FORM` (TestFlight). Reuse approaches, NOT secret values or original app bundle identities.

## User's preferences and priorities
1. No jailbreak, ordinary iPhone; camera-roll photos submitted as ordinary BeReal post.
2. Target 4.93.0 specifically. Photos selected by user; preserve order and explicitly offer front/back assignment once determined.
3. Delegate CI, builds and signing to GitHub Actions/macOS or Work cloud computer where available.
4. Do the complete job autonomously, minimize requests for reconfirmation, but request any missing mandatory authorization/certificate/device setup where genuinely required.
5. User explicitly deprioritized discussion of service/account restrictions; do not keep repeating general warnings.

## Existing implementation: do not overstate
- Current continuation: CameraRollAdapter.m now implements verified Objective-C capture hooks and normalized JPEG replacement; native compilation and unsigned IPA packaging completed. See HANDOFF_STATUS.md and CAPTURE_CONTRACT.md for evidence and remaining signing/device boundaries. The following bullets describe the original Tweak.m prototype, retained for provenance only.
- Tweak.m presents a UIKit PHPicker photo selector; preserves async selection order; emits `BRPrototypeTwoPhotosReady` with 2 UIImages. It does **not** integrate with BeReal's capture/draft/upload pipeline.
- `scripts/inspect_ipa.py` inspects unsigned structural metadata only. This does NOT prove tweak compatibility, successful injection, successful signing, login or post.
- Github Actions workflow currently builds just a dylib on macOS runner; no IPA injection or signing steps have been implemented or executed.
- Static strings observed previously: DualCameraViewModel, CapturePhotoUseCase, UploadPostCapture, UploadPostBuilderService, MyUploadPostUseCase, PendingPostUploadService and makeDraft(capture:context:profile:). Names are hypotheses for investigation, NOT verified selectors, hooks, offsets, or safe ABI contracts.

## Ordered execution plan
1. Use an authorized macOS/Xcode runner. Re-run `python3 -m unittest discover -s tests -v` and `python3 scripts/inspect_ipa.py <uploaded IPA>`; record Xcode & Theos versions.
2. Validate the Tweak builds with arm64/iOS17 and link dependencies. Fix any compile errors; collect build artifact and logs.
3. Instrument locally/offline and analyze static Swift/ObjC call sites near capture-to-draft transformation; identify verified method signatures, thread expectations and image orientation/encoding, backed by concrete evidence. Do not invent selectors, API endpoints or infer only from strings.
4. Implement clean, version-guarded photo adapter with separate mockable tests; ensure dual-camera frame order, crop, orientation, front/back, metadata handling; robust fallback when underlying API changes.
5. Test on an authorized development device, confirming selected front/back images enter draft correctly and ordinary posting succeeds. Ask user for explicit action only if posting live is otherwise necessary.
6. Bundle an injection and full nested-code re-signing process appropriate to target provisioning/signing method, without publishing private certificates/keys, and produce a signed IPA only after entitlement and signature validation. Check iOS installation and launch on non-jailbroken device.
7. Preserve original project in new **private** dedicated GitHub repository if creation privileges exist; don't push third-party binary to a public repository. GitHub Actions should upload protected artifact with SHA256.
8. Final status must distinguish 'built', 'signed', 'installed', and 'test post succeeded'; include exact build SHA, artifact location and blockers.

## Handoff boundaries
- Current Linux runtime cannot perform Xcode/theos iOS native compilation, Apple code signing, or real iPhone validation.
- GitHub workflow on macOS can resolve toolchain but cannot conjure proprietary SDK data, provisioning, private keys or a connected iPhone.
- Avoid shipping a 'signed/working IPA' claim without independent verification. Do not upload credentials, IPA, or selected photos to unrelated sites.
