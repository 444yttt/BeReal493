# Agent execution contract: BeReal 4.93.0 camera-roll posting

## Current user overrides (2026-10-14)
- User authorizes the public repository `444yttt/BeReal493`, original input/access-URL transfer to GitHub Actions, and reuse of existing Y3POSClient signing assets inside its authorized CI. Do not repeat those confirmations. Apple private keys and API credentials must remain in CI and never be printed, exported, or committed.
- The requested delivery is the signed IPA only; installation and live test posting are not acceptance requirements for this delivery. Report both as unverified.
- Continue to report whether the posting adapter is implemented and whether the IPA is signed. Do not call a picker-only prototype a working posting modification.
- The original third-party IPA is temporary build input, not repository source. Read `HANDOFF_CODEX.md` for the complete durable encrypted v3 input before asking for reattachment; prior local paths may not exist.
- User explicitly prefers SMS for Apple two-factor authentication to the **supplied private SMS target**. Keep the phone number out of public documentation, repository files, and logs. Select only an existing trusted number that uniquely matches the private request; do not add trusted numbers or alter unrelated account configuration.
- User explicitly permits sending the six-digit one-time SMS code as plaintext in this chat. This overrides earlier handoff instructions forbidding chat OTP. Accept that code without requiring an extra encryption-form step, immediately encrypt it internally to the current CI challenge using RSA-OAEP-SHA256 and AES-GCM, then publish only the encrypted reply. Never place plaintext OTP in public GitHub files, logs, workflow arguments, artifacts, or handoff records. Prefer Apple ID/password entry in the client-encrypted owner-private HTTPS form.
- If the user voluntarily supplies login input in this chat within the already granted use/deletion authorization, accept it without requiring resubmission. Within this ongoing authorized task, re-encrypt the already supplied input for a newly verified challenge when needed instead of soliciting it again; never create persistent plaintext copies. Immediately encrypt it internally to the verified current phase-0 CI public key and bound AAD using private no-echo stdin/process input. Create no persistent plaintext copies, include no input values in public files/logs/arguments, and publish only ciphertext. Do not solicit a plaintext password as the default path. Do not copy the user ID/password/phone into documentation or claim that the chat message was deleted; deletion of that message is not established.

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
- Current provisioning evidence: a GET-only audit observed one exact root registration with Apple platform `UNIVERSAL` and four missing extension registrations. Apple documents `UNIVERSAL` as all platforms; published metadata compatibility accepts exact `IOS`/`UNIVERSAL` registrations while requiring strict iOS Ad Hoc profiles, matching certificate/device/entitlements, and all five targets. A new SMS run is at phase 1 waiting for the user code; no five-profile proof or signed IPA is established. See the current handoff before continuing.
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
