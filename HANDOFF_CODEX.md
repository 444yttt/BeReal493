# Codex continuation: BeReal493 signed IPA

Updated 2026-10-14 03:12 UTC. **Signed IPA created, formally independently verified, saved and rehashed. Delivery is ready for the final user file link. Installation, launch, draft validation and live posting remain unverified.**

## Authorization and acceptance

- Public `444yttt/BeReal493`, transfer of the exact original IPA/access URL to Actions, and reuse of existing Y3POSClient signing assets inside authorized CI are already permitted. Do not repeat those confirmations.
- Deliver the signed IPA only. Real-device installation and live posting are not acceptance requirements; explicitly report them as unverified. Adapter implementation is complete and rebuilt, but its posting behavior has not been device-tested.
- Keep Apple signing/API credentials inside `444yttt/Y3POSClient` CI and delivery decryption keys local. Never print/export/commit secrets, private key paths, original IPA bytes or a plaintext signed IPA to the public repository. No public app Release is authorized.
- Prior SMS preference and voluntarily supplied login-input/OTP handling remain in AGENTS.md. Authentication sessions were cleaned up. No further credentials, SMS, Apple writes or provisioning are needed for the present delivery. Do not copy user ID/password/phone/code values or claim a chat message was deleted.

## Current verified signing result

- Adapter pin: `1f749cd1b2433d2a32694d5c91849d22f84f429f`, including the different-team sandbox-group fallback. Keep this pin; source helper fixes are separately versioned.
- Exact user original: `AlexisBarreyat.BeReal_4.93.0_und3fined.ipa`, 142120475 bytes, SHA256 `e7d77665740c61f2b0d6eae21cb6052acd2add364db3f6b5fc9ef9198ac31cbc`; bundle `AlexisBarreyat.BeReal`, version 4.93.0, build 23026, ARM64, minimum iOS 17.0. Original main executable cryptid is 0.
- Strict GET-only [readiness run 38502355511](https://github.com/444yttt/Y3POSClient/actions/runs/38502355511), Y3 commit `2688517fa5b1af32be2acbcc6b62b4ffe1745228`, verified **all five exact Ad Hoc profiles** with the primary distribution certificate, single registered device, concrete signing rights and all strict checks. Safe artifact `11866582062`, ZIP SHA256 `5dd242b3f155fa32a3f4109b319b3631da0719f8cb6e927157afaadbcfc6e811`. Current `ci-handoff/apple-access-diagnostics.json` contains that successful result. Earlier missing-ID/profile/keychain-grant failures are historical.
- Unused literal `com.apple.token` is omitted **only from the claimed signed keychain rights**; Apple profiles remain unchanged. At least one approved app/root keychain group is required; token-only, foreign and unknown grants are rejected. Certificate, device, identity, expiry and all other profile/signature checks remain strict. IOS/UNIVERSAL compatibility applies only to exact registration metadata; profile provisioning remains iOS Ad Hoc.
- The input-only flag is **absent in authoritative GitHub main**, removed at `8411dee1441afa20dfe264ee4a694bbafcdbdb0c`. A stale flag in a retained local Y3 checkout is not current remote state and must not be used to restore the gate or diagnose the completed run.
- Actual [signing run 38503871446](https://github.com/444yttt/Y3POSClient/actions/runs/38503871446) **succeeded at approximately 03:00 UTC**, Y3 commit `7a82e8d69c8853e7ea4e85e1428af77c15c78230`. CI signed/checked **90 Mach-O binaries**, passed `codesign --deep --strict`, verified all five exact profile/concrete XML-rights bundles, matched signing leaf DER, and checked ZIP CRCs.
- Signed IPA SHA256: **`fb759fff5d50d386bcc6f61b3043c89b5eb88262ec7b580097d939c605f2640e`**. Formal local decryption/independent validation passed. Final `BeReal493-CameraRoll-SIGNED.ipa` is saved in the user-download area, **140232681 bytes**, and its final-copy hash matches exactly. Only the final user file-link handoff remains; the plaintext IPA must not be committed or publicly Released.

## Independent validation and saved delivery

- Formal verifier passed **90/90 Mach-O CMS signatures, code-page hashes and special-slot hashes**, all five exact profiles and concrete XML rights for the same one device, expected signing leaf certificate, adapter load-command linkage, and all six packaged executable modes. CI deep/strict verification and independent checks are separate successful evidence. Earliest certificate/profile expiry is `2027-09-28T14:59:37Z`.
- `Payload/decrypt.day` is an unchanged original auxiliary marker. The verifier permits **only this exact path, 9-byte size and SHA256 `15218e74cef5d8df7e631ab2a31fdb8bde28976252f984231cf410630410696e`**; arbitrary extra members remain rejected. The marker is byte-identical to the supplied original, and this verifier correction did not modify signed IPA bytes. Final marker verification passed.
- Safe CI receipt: `ci-handoff/signed-verification.json`, SHA256 `18d720f5b7cfc88a63525dd12a64c0e4305994b7fe78f336d07f62d90ceee7bc`. Safe independent receipt: `ci-handoff/signed-delivery-validation.json`, SHA256 `6d7eb1ba7dc5dfd55560e381744b992e3c97ee314f3889feeb0a12bf1ea0143a`.
- Final source/helpers/verifier are published as BeReal `7d59780bc09a6d3535722637e524c24dee213447`; **89 tests and independent code review passed**, and native [run 38504938801](https://github.com/444yttt/BeReal493/actions/runs/38504938801), job `115660164759`, succeeded through artifact save. The previous 85-test checkpoint is historical; source evidence does not replace the passing delivery verifier.
- Authentication cleanup was rechecked at approximately 03:10 UTC: GET of the latest challenge/reply refs for `38500570296` returned 404, post-auth cleanup job `115646276539` succeeded, and safe result artifact `11866585002` was redownloaded/hash-checked to confirm the matching run and `credentials_retained: false`, `private_session_retained: false`. No chat-message deletion is claimed.

## Durable recovery artifacts

All artifacts below are in authorized `444yttt/Y3POSClient`. Download through the connected artifact tool/scoped CI, verify the ZIP digest and inspect members before extraction. Do not assume a prior environment's local paths or private recipient key still exist.

| Purpose | Artifact ID | ZIP SHA256 |
| --- | --- | --- |
| Signed encrypted delivery, ZIP size 140280096 bytes | `11867270650` | `75ae59e5c1006bc6b0620f7f2dccb8afd1d363a220c439c47ed0261ba951821f` |
| Complete encrypted exact original and v3 metadata | `11834521871` | `95102a46d3a1ca547e6bc058ac2dbffc522da195cce06e25385194eb89a52db6` |
| Earlier encrypted unsigned review package | `11833884915` | `688f9e637fae0fa02a2b764eb3c411877496b46e162da034dc5b491321052822` |

- Live signed-artifact metadata confirms `expired: false`, ZIP size 140280096 bytes, and expiry **2026-11-13T03:00:17Z**. Recheck this expiry if recovering after the current delivery.
- The signed archive contains the recipient-encrypted delivery, not a publicly accessible plaintext app. Use the retained local recipient key without exposing it. If it was lost, generate a fresh local recipient pair, update only its public certificate in authorized Y3, and rebuild an encrypted delivery from the existing input/profiles. An encrypted artifact alone is not user delivery.
- Original v3 artifact members are exactly `input-encrypted.bin` and `input-metadata.json`. Ciphertext is 142120480 bytes, SHA256 `07dbcb4b10c4a0b0dfb66b35c675c3415ba3fdef95ddc499c2ebbbc715e5eec5`; distribution certificate SHA256 `ffa75cd0e6ab13c541756f2eeb7768a685cae584bc50e653e63396b3c9a7e4d4`. `ci-handoff/input-envelope-v3.json` pins its artifact/repository/ZIP hash. The ZIP metadata must equal that envelope without `github_artifact`.
- V3 input was restored/hash-checked in runs `38439756854` and `38441402362`; no live iCloud URL is needed. Input artifact expiry was observed as 2026-11-12 17:35:23 UTC; recheck artifact availability/retention before relying on it.
- The old 190-chunk transfer and branch `ci-input-transfer` / commit `4b78a22e883b74197502e91c9cf6773a39fdf12d` remain partial historical data (parts 000–086 only). They are superseded and must never be presented as a complete input envelope.

## Final user handoff

1. Hand the already saved `BeReal493-CameraRoll-SIGNED.ipa` to the user through the final downloadable file link. Its final size is 140232681 bytes and SHA256 is `fb759fff5d50d386bcc6f61b3043c89b5eb88262ec7b580097d939c605f2640e`. No rebuild, auth, provisioning or further test is required for this handoff.
2. The safe records and final source are published/ready to save; preserve unrelated changes. Mark the actual user handoff only after the file/link is sent. Do not upload the plaintext IPA to public GitHub or a Release.
3. Report adapter implemented/rebuilt, signed and independently verified; explicitly state installation, launch, draft/posting, notification/widget behavior were not verified. Different-team signing cannot retain the original app-group/keychain/notification identity. Do not claim a real ordinary post was tested.

## Source provenance and resolved signing issues

- BeReal `78db445e01a9f811d7bae8dd9837ab62cd479599`: 60 local tests, native run `38494967704`/job `115628543203` succeeded. BeReal `c95492c4f1b5f7da0052a735300c7250530d3ad8`: 65 tests, native `38497716236` succeeded. BeReal `3584214d999eb349d53061e0cd03cfcccdc835db`: 69 tests, native `38499454434` succeeded. Adapter pin remains unchanged.
- Final-helper follow-up is Y3 `7a82e8d69c8853e7ea4e85e1428af77c15c78230`: keychain-rights subset handling, `--extract-certificates=` optional-prefix CLI binding, safe signing-stage diagnostics, and temporary keychain search-list isolation. The helper captures the original list before creating the temporary keychain, uses temporary+original deduplicated search paths, restores the exact original list and deletes the temporary keychain on every exit. Five keychain regressions produced the historical 85-test checkpoint; final limited-marker tests brought BeReal to 89, with Y3 focused tests still 22. The successful real signing run exercises the signer fixes.
- Earlier run `38502490546` failed generic codesign; retry `38503221530` failed first `sign_macho` with `identity_not_found`. They are superseded by successful `38503871446`; do not request a new certificate or SMS because of these resolved failures.
- `ci-handoff/source-verification.json` preserves original/follow-up evidence and the current signed-CI milestone. Authentication receipts record historical helper outcomes and cleanup; they do not override the newer five-profile/signing success.
- Owner-private authentication Site stays closed, project `appgprj_6acec7e34d248191bda5d2f848168847`, source `62285ecdb0a5e5c389a73fe7a4aeb869b2646a44`, deployment `appgdep_6acee28bfea88191bb14eb2bd2dbbf5f`. It has no credential inputs/scripts. No further auth is required for delivery and no chat-message deletion is claimed.
