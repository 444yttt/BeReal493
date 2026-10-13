# Codex continuation: BeReal493 signed IPA
Verified 2026-10-14 JST. The user's current instruction is to hand off to Codex.

## Authorized scope
- Public repository 444yttt/BeReal493; deliver an IPA only.
- User explicitly authorized transferring the original IPA and its temporary access URL to this repository's GitHub Actions.
- User explicitly authorized reusing Y3POSClient signing assets for this BeReal signing task. Do not ask for these permissions again.
- Keep the existing Apple private key/certificate credentials inside Y3POSClient CI; never print, export, or commit them.
- No device installation or live test post is required. Report signed vs installed vs tested accurately.
- Original third-party IPA is build input, not public repository source. No plaintext IPA or credential should be committed.
- No public Release containing the app was authorized.

## Repositories and known state
- BeReal adapter source pinned at 1f749cd1b2433d2a32694d5c91849d22f84f429f. Native ARM64 compilation, pair state tests and unsigned packaging had passed earlier. This pinned source also contains sandbox group fallback added for different-team signing.
- Y3POSClient main last verified at aabfb784fbc338a580a3323d104a07d3ada00d10.
- Y3 readiness run 38411966982 succeeded. Existing distribution certificate valid; exactly one enabled iOS device registered. No BeReal Ad Hoc profile creation or actual signing has run yet.
- A completed signed IPA DOES NOT exist.
- Pending implementation is scripts/bereal-resign.py. It has not executed on macOS and requires review/debugging.
- Its SOURCE_COMMIT is intentionally pinned to adapter source above. The script imports Y3's existing scripts/prepare-ci-profile.py. It must run inside authorized Y3POSClient main, not standalone inside BeReal493.

## Retained local working data (may not exist in a different Codex environment)
Root: /workspace/scratch/69d98e3bb920
- Original IPA: input/AlexisBarreyat.BeReal_4.93.0_und3fined.ipa
- SHA256: e7d77665740c61f2b0d6eae21cb6052acd2add364db3f6b5fc9ef9198ac31cbc
- Unsigned output: output/BeReal493-CameraRoll-UNSIGNED.ipa (does not include the later group fallback rebuild).
- Source workspace: handoff/BeReal493_handoff/
- signing-transfer/input-encrypted.bin (142120480 bytes), chunk-000.bin through chunk-189.bin; every chunk's hash and Git blob SHA checked.
- signing-transfer/input-metadata.json and encrypted-tree-entries.json are also preserved under ci-handoff/ in this repository.
- signing-transfer/upload-progress.json last confirmed: {"next_part":86,"total":190}.
- Git blobs for indices 000 through 085 were uploaded successfully to BeReal493. They are not yet referenced by a tree/commit. Resume from chunk-086.bin; subsequent operations may safely recreate a blob because it is content-addressed.
- signing-delivery/recipient.pem is a PUBLIC delivery-encryption certificate.
- signing-delivery/private.pem is the corresponding LOCAL ONLY output-decryption key, NOT Apple's signing key. Never commit/upload/log it. Generate a new local recipient pair if the old key is unavailable.

Original IPA also exists in user Library as libfile_7ed6e3f0c4f08191b106b1ee3d6bdb06, filename AlexisBarreyat.BeReal_4.93.0_und3fined.ipa. Retrieve only this user-supplied input, verify its hash, never substitute a downloaded app.

## Remaining sequence
1. Refresh repository heads and local progress before writing. Preserve unrelated Y3/BeReal changes.
2. Complete encrypted input transfer. If the old local data exists, upload 104 remaining chunks, verify returned SHA against ci-handoff/encrypted-tree-entries.json, persist progress per chunk. Tools allow github_create_blob with base64; prior chunk size 750000 bytes avoided request-size failures. For local exec output consumed internally, max_output_tokens:800000 prevented base64 truncation. Never print the payload to the user.
3. Create a Git tree referencing all 190 ciphertext chunks under ci-input/, then a commit and appropriate ref. Add that exact commit as transfer_commit to the input envelope. Never publish a plaintext key. The wrapped_keys value is encrypted to the existing distribution certificate's public RSA key.
4. If the old encrypted bytes are unavailable, recover original IPA and build a NEW encrypted envelope using the public signing key/readiness artifact (rerun readiness if expired); replace the whole manifest consistently. Recreating encryption does not reproduce previous ciphertext. Never pretend the existing manifest matches new bytes. Prefer an efficient authorized transfer path if the new Codex environment supports it.
5. Prepare Y3-scoped workflow with scripts/bereal-resign.py, bereal-signing-input.json and PUBLIC delivery-recipient.pem; use the same six secret names/fallbacks as .github/workflows/bereal-signing-readiness.yml. Do not mutate existing Y3 app identity/profiles. New bundle root is com.ayato.bereal493 with four matching extension IDs.
6. Before triggering, review the script for macOS/OpenSSL compatibility, helper API compatibility, concretization of provisioning entitlements, nested code signing and output encryption. Keep commands' secret-bearing inputs/logs private; expose only safe error diagnostics. The script suppresses subprocess stderr, so a failed tool command needs targeted safe diagnosis.
7. Workflow runs only authorized Y3 main on macos-15, rebuilds pinned adapter, decrypts/hash-checks original, injects, creates/reuses matching Ad Hoc profiles, signs all Mach-O/nested frameworks/extensions, verifies codesign --deep --strict and entitlements, then encrypts final IPA+receipt to recipient cert.
8. Upload ONLY encrypted output as workflow artifact; fetch, decrypt locally, compare IPA SHA256 with verification.json, inspect archive/profile/signature results. Save the signed IPA persistently and deliver it.
9. State that real-device install/launch/draft/posting and notification/widget behavior are not verified. Different-team signing cannot retain the original app-group/keychain/notification identity. Do not claim the working posting path was device-tested.

## Known tools available in originating Work session
GitHub connector fetch, create_blob, create_tree, create_commit, update_ref, workflow jobs/logs/artifact listing and download exist. No workflow_dispatch tool was needed: narrowly scoped push paths can trigger CI. Browser fallback previously hit an authentication-state protection; do not repeatedly probe login or circumvent that control.
