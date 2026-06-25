# cip30-deeplink-client

Reference TypeScript SDK for **CIP-30-DeepLink** — a deep-link wire protocol that lets a native mobile dApp ask an installed Cardano wallet to perform CIP-30 operations (`signTx`, `signData`, etc.) over the OS's URL-handling mechanism. No relay server, no embedded WebView, no QR, no WebSocket.

This repository is the **dApp-side reference implementation** that accompanies the CIP draft. The wallet-side reference implementation is [Flux-Point-Studios/yuti](https://github.com/Flux-Point-Studios/yuti); the wire format here is byte-for-byte interoperable with it.

## Status

Pre-release (`0.1.x`). The CIP is open for community review at:

- **CIP PR**: <https://github.com/cardano-foundation/CIPs/pull/1189>
- **Forum thread**: <https://forum.cardano.org/t/cip-proposal-mobile-deep-link-signing-for-native-dapps-cip-30-extension/154561>
- **Live inspector** (debug your integration, no install): <https://cip30-inspector.vercel.app>
- **AI agents / LLMs**: machine-readable integration docs at <https://cip30-inspector.vercel.app/llms.txt> (`/llms-full.txt` for everything in one fetch)

**Wallet support.** Works with any wallet that implements the CIP-186 signed `connect`. Gero is verified end-to-end against this SDK; [Yuti](https://github.com/Flux-Point-Studios/yuti) is the wallet-side reference. The SDK is **fail-closed** — it will not seat a session from a wallet that has not shipped the signed handshake, so end-user signing requires one of those wallets. You can build and test your entire integration today without either (see below).

## Install

```bash
npm install @fluxpointstudios/cip30-deeplink-client
```

Runtime dependency: `tweetnacl` (NaCl-box + Ed25519). Runs in the browser and Node.

## How it works

A deep-link round-trip is **not** a single call: the dApp navigates to the wallet, the wallet processes the request and redirects back to the dApp's `redirect` URL with the response in the query string. In a browser that is a full page navigation, so the SDK persists the in-flight request and you recover the result on the **next page load** with `resume()`.

```typescript
import { DeepLinkClient } from "@fluxpointstudios/cip30-deeplink-client";

const client = new DeepLinkClient({
  wallet: "yuti",                 // deep-link scheme: cip30dl-yuti
  chain: "cardano:preprod",
  // resolveTxHash: resolveTxHash, // wire your tx builder's hash for signTx
});

// 1. On every page load, first recover any pending wallet response.
const resumed = await client.resume();
if (resumed?.kind === "connect") {
  // resumed.session — { addresses, signingPublicKey, chain, ... } (now stored)
}
if (resumed?.kind === "signTx") {
  const { witnessSet, txHash, signatureValid } = resumed.result;
}

// 2. Start a flow (navigates to the wallet; returns on the redirect → resume()).
await client.connect({ name: "Aegis", url: "https://aegis.fluxpointstudios.com" });

// 3. Once connected, request a signature.
await client.signTx({ tx: cborHex });        // needs resolveTxHash, or pass commit
```

That is the whole integration: **`resume()` first on every load**, then `connect()` / `signTx()`
to start a flow. Both navigate to the wallet and return via the redirect, so the result always
arrives through `resume()` on the next load — never as the return value of `connect`/`signTx`.

> **Build and test with no wallet and no phone.** The
> [live inspector](https://cip30-inspector.vercel.app) reproduces exactly
> what `resume()` does — paste a `connect` response and every verification step (method tag, decrypt,
> Ed25519 signature, nonce echo) lights up green/red, with the canonical subject and decrypted
> session laid out. To round-trip `connect → signTx` offline, drive the bundled fake wallet
> (`test/fake-wallet.ts`). `wallet` sets the deep-link scheme (`cip30dl-<wallet>`); for wallets that
> advertise an https universal link, also pass `httpsPrefix`.

### Computing the commit (tx hash)

`signTx` binds the request to `commit = BLAKE2b-256(tx_body)` — the Cardano transaction hash. The SDK stays dependency-light and does **not** bundle a serialization library, so either:

- wire your tx builder's hasher once: `new DeepLinkClient({ ..., resolveTxHash: (cbor) => resolveTxHash(cbor) })` (MeshJS `resolveTxHash`, Lucid, or CSL `hash_transaction`), or
- pass it per call: `client.signTx({ tx, commit })` where `commit` is base64url of the 32-byte hash.

### Assembling & submitting

The wallet returns a **witness set**, not a signed tx. Splice it into the body with your serialization library, or send `{ txCbor, witnessSet }` to your backend to assemble + submit (what the Aegis demo does — keeps CSL/Mesh off the client).

### Verification

Both legs of the handshake are authenticated, and `resume()` **rejects** anything that doesn't check out:

- **connect** — the response must carry the wallet's Ed25519 signature over the canonical subject (which covers `walletKey`, `method`, the encrypted payload, and an `echo` of the request nonce), a `method=connect` domain tag, and that nonce echo. The SDK decrypts the session, verifies the signature against the `signingPublicKey` it advertises, and confirms the echo — so an unsigned, tampered, or replayed connect can never seat a session, and the verified key is pinned for the rest of the session.
- **signTx** — every response is Ed25519-signed over the canonical subject, keyed by the `signingPublicKey` pinned at connect. A returned witness is always signature-verified.

Connect is first contact, so the signature proves the response is consistent, untampered, and bound to this request — not, on its own, that the responder is the user's genuine wallet (that rests on the OS routing the scheme plus the in-wallet consent screen). What the pin buys is that every later `signTx` reply is provably from the same key-holder this connect established.

## API surface

- `new DeepLinkClient(options)` — `{ wallet, chain, redirectUrl?, storage?, resolveTxHash? }`
- `connect(dappInfo)` / `signTx(opts)` — start a flow (navigate to the wallet)
- `resume(url?)` — recover the pending response; returns the connect session, the signTx result, or `null`
- `getSession()` / `disconnect()`
- Low-level pure helpers (custom transports, server-side, testing): `buildConnectUrl`, `buildSignTxUrl`, `decodeConnectResponse`, `decodeSignTxResponse`, `canonicalSubject`, `b64uEncode/Decode`

Outside a browser, pass `redirectUrl`, a `storage` (a `localStorage`-shaped object), and a `navigate` adapter.

## Example

`examples/aegis-web/` is the Aegis demo dApp driven entirely by this SDK (connect → signTx → verify). Build the SDK, then serve the folder over http:

```bash
npm install && npm run build
npx serve examples/aegis-web    # ESM modules need http, not file://
```

## Develop

```bash
npm install
npm test          # vitest — incl. a connect+signTx round-trip vs a Yuti-compatible wallet
npm run typecheck
npm run build     # dist/ (ESM + CJS + d.ts) via tsup
```

## Scope of this repository

Per [CIP-0001](https://cips.cardano.org/cip/CIP-0001), reference implementations live in repositories belonging to the author. This SDK is intended as a **reference**, not a production dependency. Production dApps are encouraged to fork, adapt, or re-implement against the CIP itself.

The companion dApp that this SDK was extracted from is **Aegis** (parametric DeFi insurance), at <https://github.com/Flux-Point-Studios/aegis-contracts> for the on-chain validator suite.

## License

Apache-2.0. See [LICENSE](./LICENSE).
