# BeReal 4.93.0 quota storage evidence

All offsets below are image/file offsets in the exact original main executable (image base `0x100000000`). Main SHA256: `d64203bfef02feb41680a43224762e8e5be2f9723e6f62924d8d5bfc2d1b2cd6`. Original IPA SHA256: `e7d77665740c61f2b0d6eae21cb6052acd2add364db3f6b5fc9ef9198ac31cbc`. Original bytes were read only. This establishes a local re-signing compatibility defect; device/account runtime behavior remains untested.

## Concrete dataflow

1. `CoreFeedData.PostsRepositoryImpl` type descriptor is at `0x359f4e8`; field descriptor `0x39483ac` declares `_remainingPostsCount: LocalStorage.KeychainStorage<Int>` (the indirect symbolic type reference resolves to `LocalStorage.KeychainStorage`, with `Si` generic argument).
2. Initializers `0x1324de4` and `0x132a6a4` obtain the keychain singleton with `0x8c8018`, assign the key `remainingPostsCount`, and store default integer **0** at wrapper offset `+0x10` (`0x1324e40`, `0x132a760`). The singleton is stored at image offset `0x44defd0`.
3. Server response continuation `0x1327928` calls imported `Protobufs.Public_Home_V2_GetMyStateResponse.remainingPosts: Int32` getter (stub `0x3153ee0`) at `0x1327960`, sign-extends it to `Int`, then invokes `KeychainStorage.wrappedValue` setter `0x8c84d0` at `0x13279a8`. The value is not being synthesized by the adapter.
4. The `CoreFeedDomain.PostsRepository` conformance at `0x331ae20` resolves its indirect protocol pointer to descriptor `0x358e59c`. Its witness table `0x3e17bf8` has the count getter at `+8`, pointing to `0x1329c74`. That getter copies the repository's same wrapper and calls generic keychain getter `0x8c8248` at `0x1329d14`, returning the integer in `x0`.
5. Concrete async `BeReal.CanPostBeRealInteractor` flow `0x28b730` / continuation `0x28b9c0` resolves `FactoryKit.Factory<CoreFeedDomain.PostsRepository>` (mangled type record `0x324a9d0`, symbolic bytes at `0x35fb78a`). At `0x28bc28` it loads the repository count getter witness at `+8`, calls at `0x28bc38`, saves the returned integer in `x20`, then passes it as **x4** at `0x28bc90` to RemainingPostsService's witness call `0x28bca0`.
6. `CoreMyPostDomain.RemainingPostsServiceImpl` conformance `0x3308880`, witness table `0x3e08588`, method at `+8` -> `0x11101c4` -> calculator `0x11101dc`. For ordinary existing-user/current-moment branches, it subtracts counted posts/pending uploads from input x4, clamps negatives to zero, and returns the `CanPostBeRealModel` representation at `0x11111f0–0x11111f8`: x0=max(remaining,0), w1=(remaining<1). Zero is the `.no` empty case (x0=0,w1=1); `.yes(remaining)` uses w1=0. Model declaration fieldmd `0x393dc68` lists `yes(Int remaining)`, `no`, `memoriesOnly`.

The CanPostBeReal protocol witness table contains deleted async stubs, but optimized concrete calls are present (for example `0x35ad58 -> 0x28b730`), so the direct concrete flow above is real executable code. Do not infer that the implementation is absent from the protocol stubs.

## Re-signing mismatch

The LocalStorage keychain singleton factory `0x8c7f9c` constructs `group.BeReal` in x2/x3 and calls Keychain initializer `0x8ceec0` at `0x8c7fe8`. This is distinct from the already patched authentication-token keychain factory `0x26d2754`.

The argument meaning is established beyond string names: initializer `0x8ceec0` preserves x2/x3 in x23/x22, then writes them into `KeychainAccess.Options +0x18/+0x20` at `0x8cefd4`. Options fieldmd `0x3918b30` declares this field as `accessGroup: String?`. Query builder `0x8d0508` loads those same words at `0x8d0610`/`0x8d0618`, skips the attribute only when the optional string is nil, and otherwise inserts it into the query dictionary at `0x8d0678`. Its key global is initialized by `0x8d86b4` from imported `_kSecAttrAccessGroup` at GOT `0x3d3f610`.

Generic keychain getter `0x8c8248` calls keychain read `0x8d0178`, which calls imported `_SecItemCopyMatching` (stub `0x31590ac`) at `0x8d03a8`. Any thrown read/decode error reaches `0x8c8440`, which copies the wrapper's stored default value. The quota wrapper default is 0. Under the re-signed entitlement set without the original group, foreign-group reads/writes cannot provide the server quota, and the native eligibility path sees 0. This is not a photo-pair consumption counter or push-notification gate.

## Candidate repair boundary

Use the app's permitted default keychain for **this singleton only**, preserving service/key/default value/native server quota and calculator:

- Original function context: file/image `0x8c7f9c`, length 124, SHA256 `d8c6f971527dc78e863cd2c044c9d611c7c3e6407c99b4f5e10702f834544e5e`.
- Last x2 writer `0x8c7fcc`: original `movk x2,#0x6542,lsl#48`, expected bytes `42a8ecf2`; candidate `mov x2,xzr`.
- Last x3 writer `0x8c7fd8`: original `movk x3,#0xec00,lsl#48`, expected bytes `0380fdf2`; candidate `mov x3,xzr`.
- Full original hash/version/context and both original instruction checks should guard packaging. Verify only these eight new bytes change in the original main before injection/signing; preserve previous auth patch separately.

No product source, original bytes, entitlements or signed output were changed by this analysis. The remaining native UI path and any actual server-granted quota must still be evaluated separately; no live test or guaranteed additional-post eligibility is claimed.
