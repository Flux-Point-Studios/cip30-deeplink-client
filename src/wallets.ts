// Wallet registry — the set of CIP-30 deep-link wallets the picker can target
// directly, plus the invocation + signature-format metadata each one declares.
//
// The deep-link scheme for a wallet id is always `cip30dl-${id}` (see
// `walletScheme` in protocol.ts). A wallet that ships universal links also
// declares an HTTPS `universalLink` base (the `httpsPrefix` the client uses):
// the request path is `${universalLink}<method>?...` (e.g. `…/connect?…`).

import type { SignFormat } from './types.js';

export type WalletStatus = 'verified' | 'reference' | 'announced';

export interface WalletRegistryEntry {
  /** Wallet id. The deep-link scheme is `cip30dl-${id}` (`walletScheme`). */
  id: string;
  /** Display name for the picker. */
  name: string;
  /** Always-available custom scheme, e.g. `cip30dl-gero:` (no association needed). */
  customScheme: string;
  /**
   * Primary HTTPS universal-link base — the `httpsPrefix` passed to the client.
   * The method is appended: `${universalLink}connect?…`. Omit for scheme-only wallets.
   */
  universalLink?: string;
  /** The `applinks:` host the wallet's AASA covers, e.g. `cip30dl.gerowallet.io`. */
  applinksHost?: string;
  /** URL serving the apple-app-site-association for the universal link. */
  aasaUrl?: string;
  /**
   * Connect/sign signature format.
   *  - `'spec'`: the CIP-0186 canonical-subject Ed25519 (the wallets call this
   *    `sign_006`): domain separator `"cip30dl-v1\n"`, then
   *    `scheme://host(lowercased)[:port]<percent-encoded path>?<encodedQuery>`,
   *    where `encodedQuery` drops `signature`, key-sorts lexicographically
   *    (stable; ties keep original order), strict-unreserved percent-encodes key
   *    and value (`[A-Za-z0-9._~-]` raw), joined with `&`. Signed with the
   *    per-session Ed25519 key and appended LAST.
   *  - `'sdk-legacy'`: the 0.1.0 SDK form.
   */
  signFormat: SignFormat;
  /**
   * Conformance confidence:
   *  - `'verified'`: the wallet's emitted connect verifies end-to-end against
   *    the published SDK (a verify-only fixture lives in `conformance/`).
   *  - `'reference'`: a first-party reference implementation.
   *  - `'announced'`: registered but not yet verified.
   */
  status: WalletStatus;
  /** Free-form notes (e.g. a hedged-Ed25519 caveat). */
  notes?: string;
}

export const WALLET_REGISTRY: Record<string, WalletRegistryEntry> = {
  gero: {
    id: 'gero',
    name: 'Gero',
    customScheme: 'cip30dl-gero:',
    universalLink: 'https://cip30dl.gerowallet.io/cip30dl/v1/',
    applinksHost: 'cip30dl.gerowallet.io',
    aasaUrl:
      'https://cip30dl.gerowallet.io/.well-known/apple-app-site-association',
    signFormat: 'spec',
    status: 'verified',
    notes:
      "iOS CryptoKit Ed25519 is HEDGED (randomized, RFC 8032 §8.5): every " +
      "emitted connect carries a fresh, valid signature even for identical " +
      "input. Conformance is therefore 'the signature VERIFIES against the " +
      "session signingPublicKey in the payload', NOT a byte-match against a KAT.",
  },
  yuti: {
    id: 'yuti',
    name: 'Yuti',
    customScheme: 'cip30dl-yuti:',
    signFormat: 'spec',
    status: 'reference',
    notes: 'First-party reference implementation (Flux Point Studios).',
  },
};

/** Look up a registry entry by wallet id (undefined if not registered). */
export const lookupWallet = (id: string): WalletRegistryEntry | undefined =>
  WALLET_REGISTRY[id];
