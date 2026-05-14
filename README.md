# cip30-deeplink-client

Reference TypeScript SDK for **CIP-30-DeepLink** — a deep-link wire protocol that lets a native mobile dApp ask an installed Cardano wallet to perform CIP-30 operations (`signTx`, `signData`, etc.) over the OS's URL-handling mechanism. No relay server, no embedded WebView, no QR, no WebSocket.

This repository is the **dApp-side reference implementation** that accompanies the CIP draft. The wallet-side reference implementation is [Flux-Point-Studios/yuti](https://github.com/Flux-Point-Studios/yuti).

## Status

Pre-release. The CIP itself is open for community review at:

- **CIP PR**: <https://github.com/cardano-foundation/CIPs/pull/1189>
- **Forum thread**: <https://forum.cardano.org/t/cip-proposal-mobile-deep-link-signing-for-native-dapps-cip-30-extension/154561>

The SDK source will land here once the CIP clears Triage. Until then, this repo holds:

- the canonical link target for the CIP's *Reference Implementation* section
- the design notes that drive the SDK's public surface

## Anticipated public surface

```typescript
import { DeepLinkClient } from "@fluxpoint/cip30-deeplink-client";

const client = new DeepLinkClient({ wallet: "yuti", chain: "cardano:preprod" });
const session = await client.connect({
  name: "Aegis",
  url: "https://aegis.fluxpointstudios.com",
});
const { witnessSet, txHash } = await client.signTx({ tx: cborHex, partialSign: false });
const signedTx = client.assemble(cborHex, witnessSet);
await fetch("/api/tx/submit", { method: "POST", body: signedTx });
```

## Scope of this repository

Per [CIP-0001](https://cips.cardano.org/cip/CIP-0001), reference implementations live in repositories belonging to the author. This SDK is intended as a **reference**, not a production dependency. Production dApps are encouraged to fork, adapt, or re-implement against the CIP itself.

The companion dApp that this SDK was extracted from is **Aegis** (parametric DeFi insurance), at <https://github.com/Flux-Point-Studios/aegis-contracts> for the on-chain validator suite.

## License

Apache-2.0. See [LICENSE](./LICENSE).
