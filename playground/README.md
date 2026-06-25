# CIP-30-DeepLink Inspector

"jwt.io for CIP-186 deep links." Paste a wallet's `connect` response and watch every
verification step a conforming dApp runs light up green/red — method tag, payload decrypt,
Ed25519 signature, nonce echo — with the canonical subject and decrypted session laid out.

It is **pure client-side**: all logic is the published
[`@fluxpointstudios/cip30-deeplink-client`](https://www.npmjs.com/package/@fluxpointstudios/cip30-deeplink-client)
pure functions bundled into one static file. No backend, no network. Host it anywhere static
(GitHub Pages, S3, `file://` over a tiny server).

## Run locally

```bash
npm install
npm run build:playground          # bundles playground/inspector.ts -> playground/inspector.js
npx serve playground              # or any static server; then open the printed URL
```

## Two workflows

**Wallet devs — "is my output correct?"**
1. Set your `redirect` and click **Build request** — it mints a connect request with a known dApp
   key + nonce (stashed in the page).
2. Run that request through your wallet (deep-link it on a device, or your test harness).
3. Paste the wallet's response into **Inspect a response** and hit **Inspect**. It verifies against
   the stashed key automatically and shows exactly which step fails (with the spec error code).

**dApp devs — "why did this response reject?"**
Paste the response URL, your dApp's X25519 secret (hex or base64url), and the request nonce. The
inspector reproduces precisely what `resume()` does, step by step.

The four **Examples** buttons load fixed-key, reproducible cases (valid, echo-mismatch `-5`,
tampered-signature `-10`, legacy/unsigned `-10`) straight from
[`../conformance/connect-kat.json`](../conformance/) so you can see correct *and* every failure mode.

## Correctness

The per-step engine ([`inspect-core.ts`](./inspect-core.ts)) is unit-tested to reach the **same
verdict and error code** as the shipped decoder on every case
([`../test/inspector-core.test.ts`](../test/inspector-core.test.ts)) — the playground can't teach a
verdict the SDK wouldn't reach.
