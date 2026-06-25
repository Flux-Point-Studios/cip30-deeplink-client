# CIP-30-DeepLink conformance kit

Everything needed to implement the hardened `connect` handshake correctly in **any** language, and
prove you did. Language-agnostic vectors + the one byte-fragile algorithm (the canonical subject)
shown in two already-validated implementations.

## Files

| File | What it is |
|---|---|
| `connect-kat.json` | **Known-answer vector.** Fixed, non-secret keys/nonces ⇒ a byte-exact `signature`, `payload`, canonical subject, and response URL, plus the `-5`/`-10` reject cases. Self-verified against the shipped decoder by [`../test/conformance-connect.gen.test.ts`](../test/conformance-connect.gen.test.ts). |
| `spec-vector-canonical-connect.json` | The CIP-0186 `tests/vectors` entry (canonical-subject category) for the signed connect response. |
| `yuti-connect-signing.reference.diff` | The wallet-side reference change (Dart): emit `method=connect` + `echo` + the signature. |

Spec: **CIP-186 §connect / §Response signing** ([PR #1189](https://github.com/cardano-foundation/CIPs/pull/1189)).
Interactive: the [inspector playground](../playground/).

## Use the vector in your language

`connect-kat.json` is the oracle. Independent of any SDK:

1. Load `inputs` (all hex / base64url). Derive the Ed25519 key from `walletEd25519Seed_hex`; assert
   its public key base64url-equals `inputs.signingPublicKey_b64url`.
2. Box-encrypt `inputs.sessionJson` to `dappX25519Public` under `responseNonce` with `walletX25519Secret`;
   assert it equals `derived.payload_b64url`.
3. Build the canonical subject (below) over the response params; assert it equals
   `derived.canonicalSubject_utf8`.
4. Ed25519-sign that subject; assert it equals `derived.signature_b64url` (Ed25519 is deterministic).
5. Drive each `cases[]` entry through your dApp-side verifier: `valid` ⇒ accept; `echo_mismatch` ⇒
   `-5`; `tampered_signature` / `legacy_unsigned` ⇒ `-10`.

If all five hold, your wallet output is byte-identical to what every conforming dApp expects.

## The canonical subject (the one part that bites)

Six steps (spec §Response signing): `"cip30dl-v1\n"` ‖ `scheme://host[:port]path` ‖ `"?"` ‖ params
(minus `signature`) sorted by key in lexicographic **byte** order, each key and value
strict-unreserved percent-encoded (`[A-Za-z0-9._~-]` literal, else `%XX` **upper**case), joined by `&`.
Host lowercased; default ports (`443`/`80`) omitted; path byte-preserved.

> ⚠ The empty-path case is the classic interop break: an authority-only redirect (`https://host`,
> no `/`) is `''` under RFC-3986 / Dart `Uri.path` but `'/'` under WHATWG `URL.pathname`. **Verifiers
> SHOULD accept both** (the SDK's `canonicalSubjectCandidates` does); **signers** emit whichever
> their URL library yields and MUST keep it consistent with what they sign.

**TypeScript** — validated against the KAT ([`../src/canonical.ts`](../src/canonical.ts)):

```ts
const SEP = 'cip30dl-v1\n';
const UNRESERVED = /[A-Za-z0-9._~-]/;
const enc = (s: string) => [...new TextEncoder().encode(s)]
  .map((b) => (UNRESERVED.test(String.fromCharCode(b)) ? String.fromCharCode(b) : '%' + b.toString(16).toUpperCase().padStart(2, '0')))
  .join('');
function canonicalSubject(url: string): string {
  const u = new URL(url);
  const pairs: [string, string][] = [];
  u.searchParams.forEach((v, k) => { if (k !== 'signature') pairs.push([k, v]); });
  pairs.sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0));
  const port = u.port ? ':' + u.port : '';
  const q = pairs.map(([k, v]) => `${enc(k)}=${enc(v)}`).join('&');
  return `${SEP}${u.protocol.replace(':', '')}://${u.hostname.toLowerCase()}${port}${u.pathname}?${q}`;
}
```

**Dart** — validated against the KAT (the Yuti reference, [`yuti-connect-signing.reference.diff`](./yuti-connect-signing.reference.diff)):

```dart
String canonicalSubject(Uri url) {
  final pairs = <List<String>>[];
  url.queryParametersAll.forEach((k, vs) {
    if (k == 'signature') return;
    for (final v in vs) pairs.add([k, v]);
  });
  pairs.sort((a, b) => a[0].compareTo(b[0]));
  final q = pairs.map((p) => '${_enc(p[0])}=${_enc(p[1])}').join('&');
  final port = url.hasPort ? ':${url.port}' : '';
  return 'cip30dl-v1\n${url.scheme}://${url.host.toLowerCase()}$port${url.path}?$q';
}
// _enc = strict-unreserved percent-encode (uppercase hex), same set as above.
```

Porting to Kotlin / Swift / Rust: implement the six steps, then run `connect-kat.json` step 3 as the
oracle — if your canonical subject matches `derived.canonicalSubject_utf8` byte-for-byte, your
signatures will verify everywhere.
