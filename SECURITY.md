# Security policy

## Reporting a vulnerability

If you believe you've found a security issue in `cip30-deeplink-client` or in the underlying [CIP-30-DeepLink protocol](https://github.com/cardano-foundation/CIPs/pull/1189), please report it privately. **Do not file a public GitHub issue.**

- Email: security@fluxpointstudios.com
- PGP key: available on request
- Response SLA: we acknowledge reports within 72 hours and provide a triage outcome within 7 days

Please include in your report:

1. A description of the issue and its potential impact (data exposure, signature forgery, replay, downgrade, etc.)
2. Reproduction steps (a minimal test case is ideal once the SDK source lands)
3. Affected version / commit hash / runtime (browser, Node, Capacitor WebView, etc.)
4. Whether the vulnerability has been disclosed elsewhere

We will work with you in good faith on a disclosure timeline. Reports that follow [coordinated disclosure](https://www.iso.org/standard/72311.html) best practices and give us a reasonable patch window will be credited (with your consent) in release notes.

## Scope

In scope:

- The TypeScript SDK source published in this repository (once Wave 2 lands)
- The CIP-30-DeepLink protocol itself when the finding is rooted in the protocol shape rather than this SDK's specific implementation
- Documentation that could mislead a dApp author into an insecure integration

Out of scope:

- Vulnerabilities in transitive dependencies that have not been adapted by this SDK (please report those upstream)
- Issues that depend on a malicious wallet — by construction, CIP-30-DeepLink does not defend against this case
- Issues that depend on a user accepting an obviously suspicious in-wallet signing prompt
- Social-engineering attacks

## Coordinated disclosure with wallet implementors

CIP-30-DeepLink is a multi-party protocol. If a finding affects the wire shape rather than this SDK alone, we will coordinate disclosure with:

- The wallet-side reference implementation at [Flux-Point-Studios/yuti](https://github.com/Flux-Point-Studios/yuti)
- The CIP editors on [cardano-foundation/CIPs#1189](https://github.com/cardano-foundation/CIPs/pull/1189)
- Any other wallet implementors named in the CIP's Implementors preamble at the time of disclosure

## Companion repositories

- **CIP draft & spec**: [cardano-foundation/CIPs#1189](https://github.com/cardano-foundation/CIPs/pull/1189)
- **Wallet-side reference**: [Flux-Point-Studios/yuti](https://github.com/Flux-Point-Studios/yuti)
- **Forum discussion**: [forum.cardano.org](https://forum.cardano.org/t/cip-proposal-mobile-deep-link-signing-for-native-dapps-cip-30-extension/154561)
