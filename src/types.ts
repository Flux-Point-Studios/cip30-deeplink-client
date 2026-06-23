/** A CAIP-2-style Cardano chain id. */
export type ChainId =
  | 'cardano:mainnet'
  | 'cardano:preprod'
  | 'cardano:preview'
  | (string & {});

/** dApp identity sent at connect (base64url-JSON in the `dapp` parameter). */
export interface DappInfo {
  name: string;
  url: string;
  iconUrl?: string;
}

/** Minimal synchronous key/value store (browser localStorage satisfies this). */
export interface KeyValueStore {
  getItem(key: string): string | null;
  setItem(key: string, value: string): void;
  removeItem(key: string): void;
}

export interface DeepLinkClientOptions {
  /** Wallet id; the deep-link scheme is `cip30dl-<wallet>` (e.g. `yuti`). */
  wallet: string;
  /** Target chain; sent at connect and surfaced back in the session. */
  chain: ChainId;
  /**
   * Where the wallet returns its response. Defaults to the current page URL
   * (`location.href` with the query stripped) in a browser. Must be an https
   * URL the wallet can bind to the dApp host, or a custom scheme the dApp
   * registered. Required outside a browser.
   */
  redirectUrl?: string;
  /** Persists pending request state across the redirect. Defaults to
   *  `localStorage` in a browser; required elsewhere. */
  storage?: KeyValueStore;
  /**
   * Computes the CIP-186 commit = BLAKE2b-256(tx_body) = the Cardano tx hash,
   * for signTx. Wire your tx builder's hasher (e.g. MeshJS `resolveTxHash`,
   * Lucid, or CSL `hash_transaction`). Optional if every signTx call passes an
   * explicit `commit`.
   */
  resolveTxHash?: (txCbor: string) => string;
  /**
   * signTx/signData wire format the target wallet implements:
   *   - `sdk-legacy` (default): hex `tx` in the request; the response decrypts
   *     to the raw `transaction_witness_set` CBOR. Yuti follows this.
   *   - `spec`: CIP-0186 vectors — `tx` is `base64url(CBOR)`; the response is the
   *     `{ commit, witnessSet, txHash }` envelope and the dApp MUST verify the
   *     `commit` echo (mismatch ⇒ `-2 CommitMismatch`). Gero follows this.
   * `connect` is byte-identical across both formats.
   */
  signFormat?: SignFormat;
  /**
   * Optional https universal-link prefix the wallet advertises (e.g.
   * `https://cip30dl.gerowallet.io/cip30dl/v1/`). When set, connect/signTx
   * requests use the https form (`<prefix>connect`) instead of the custom
   * scheme (`cip30dl-<wallet>:/v1/connect`). iOS Safari opens universal links
   * reliably but silently drops custom-scheme navigations, so wallets that
   * ship a prefix should use it. Omit to use the custom scheme (Yuti).
   */
  httpsPrefix?: string;
}

/** signTx/signData wire format — see {@link DeepLinkClientOptions.signFormat}. */
export type SignFormat = 'sdk-legacy' | 'spec';

/** The session the wallet establishes at connect (decrypted session JSON). */
export interface Session {
  /** Opaque session id. */
  session: string;
  /** 1 = mainnet, 0 = test networks. */
  network: number;
  /** The wallet's used address(es) for this session. */
  addresses: string[];
  chain: ChainId;
  walletId: string;
  /** Unix-seconds expiry. */
  expiresAt: number;
  /** base64url Ed25519 key that signs every subsequent response. */
  signingPublicKey: string;
  /** base64url wallet X25519 public key (the connect `walletKey`), used to
   *  encrypt later signTx requests. SDK-added, not part of the signed JSON. */
  walletKey: string;
}

export interface SignTxOptions {
  /** Unsigned transaction CBOR (hex). */
  tx: string;
  /** Request a partial (witness-only) signature. Default true. */
  partialSign?: boolean;
  /** Optional vkey hints (CIP-30 `signTx` semantics). */
  vkeyHints?: string[];
  /** Override the computed commit (base64url of the 32-byte tx hash). */
  commit?: string;
  /** Seconds from now the request stays valid (default 600). */
  ttlSeconds?: number;
}

export interface SignTxResult {
  /** The witness-set CBOR (hex) returned by the wallet. */
  witnessSet: string;
  /** The transaction hash (hex) that was signed (= the commit). */
  txHash: string;
  /** Whether the wallet's Ed25519 response signature verified. Always true on
   *  a resolved result — a bad signature rejects the promise instead. */
  signatureValid: boolean;
}

/** A wallet-side rejection (`response=rejected`), surfaced as a thrown error. */
export class DeepLinkRejection extends Error {
  readonly errorCode: number;
  readonly walletMessage: string;
  constructor(errorCode: number, walletMessage: string) {
    super(`wallet rejected the request (code ${errorCode}): ${walletMessage}`);
    this.name = 'DeepLinkRejection';
    this.errorCode = errorCode;
    this.walletMessage = walletMessage;
  }
}
