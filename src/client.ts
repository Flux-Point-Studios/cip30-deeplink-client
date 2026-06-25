import { b64uDecode, b64uEncode } from './base64url.js';
import { boxKeyPairFromSecret, newBoxKeyPair, randomNonce } from './crypto.js';
import {
  buildConnectUrl,
  buildSignTxUrl,
  bytesToHex,
  decodeConnectResponse,
  decodeSignTxResponse,
  hexToBytes,
  isResponseUrl,
  walletScheme,
} from './protocol.js';
import type {
  DappInfo,
  DeepLinkClientOptions,
  KeyValueStore,
  Session,
  SignFormat,
  SignTxOptions,
  SignTxResult,
} from './types.js';

/** Result of recovering a pending response after the wallet redirect. */
export type ResumeResult =
  | { kind: 'connect'; session: Session }
  | { kind: 'signTx'; result: SignTxResult }
  | null;

type Pending =
  | { kind: 'connect'; nonceB64: string }
  | { kind: 'signTx'; commitHex: string };

function defaultStorage(): KeyValueStore {
  const ls = (globalThis as { localStorage?: KeyValueStore }).localStorage;
  if (!ls) {
    throw new Error(
      'no storage available — pass `storage` in DeepLinkClientOptions ' +
        '(needed to persist request state across the wallet redirect)',
    );
  }
  return ls;
}

function defaultRedirectUrl(): string {
  const loc = (globalThis as { location?: Location }).location;
  if (!loc) {
    throw new Error('no `location` — pass `redirectUrl` in DeepLinkClientOptions');
  }
  return loc.origin + loc.pathname;
}

/**
 * dApp-side CIP-30-DeepLink client. Drives connect -> signTx over the OS's URL
 * handler: each call persists per-session state and navigates to the wallet;
 * the wallet returns via the redirect, and `resume()` recovers the result on
 * the next page load. The wire format is byte-identical to the Yuti reference
 * wallet (strict base64url, NaCl-box envelope, canonical-subject Ed25519).
 */
export class DeepLinkClient {
  private readonly scheme: string;
  private readonly chain: string;
  private readonly storage: KeyValueStore;
  private readonly redirectUrl: string;
  private readonly resolveTxHash?: (txCbor: string) => string;
  private readonly navigate: (url: string) => void;
  private readonly nowSeconds: () => number;
  private readonly signFormat: SignFormat;
  private readonly httpsPrefix?: string;

  private readonly kDappKey: string;
  private readonly kSession: string;
  private readonly kPending: string;

  constructor(options: DeepLinkClientOptions & {
    /** Injectable navigation (default: set `location.href`). */
    navigate?: (url: string) => void;
    /** Injectable clock for ttl (default: `Date.now()`). */
    now?: () => number;
  }) {
    this.scheme = walletScheme(options.wallet);
    this.chain = options.chain;
    this.storage = options.storage ?? defaultStorage();
    this.redirectUrl = options.redirectUrl ?? defaultRedirectUrl();
    this.resolveTxHash = options.resolveTxHash;
    this.navigate =
      options.navigate ??
      ((url: string) => {
        const loc = (globalThis as { location?: Location }).location;
        if (!loc) throw new Error('no `location` to navigate; pass `navigate`');
        loc.href = url;
      });
    this.nowSeconds = options.now ?? (() => Math.floor(Date.now() / 1000));
    this.signFormat = options.signFormat ?? 'sdk-legacy';
    this.httpsPrefix = options.httpsPrefix;

    this.kDappKey = `cip30dl:dappkey:${options.wallet}`;
    this.kSession = `cip30dl:session:${options.wallet}`;
    this.kPending = `cip30dl:pending:${options.wallet}`;
  }

  /** The active session, if a prior connect was resumed AND it has not expired.
   *  An expired session is cleared and treated as no session, so callers fall
   *  back to a reconnect instead of round-tripping a doomed signTx. */
  getSession(): Session | null {
    const raw = this.storage.getItem(this.kSession);
    if (!raw) return null;
    const session = JSON.parse(raw) as Session;
    if (
      typeof session.expiresAt === 'number' &&
      session.expiresAt > 0 &&
      this.nowSeconds() >= session.expiresAt
    ) {
      this.storage.removeItem(this.kSession);
      return null;
    }
    return session;
  }

  /** Forget the session and dApp keypair (full disconnect). */
  disconnect(): void {
    this.storage.removeItem(this.kSession);
    this.storage.removeItem(this.kDappKey);
    this.storage.removeItem(this.kPending);
  }

  /**
   * Start a `connect`: navigates to the wallet. The session is delivered by
   * `resume()` on the redirect back. (Returns once navigation is issued.)
   */
  async connect(dappInfo: DappInfo): Promise<void> {
    const dapp = this.ensureDappKeyPair();
    // Persist the request nonce: the wallet must echo it in the (signed) connect
    // response, and resume() compares the echo against this to bind the pairing
    // to this attempt and reject replays.
    const nonce = randomNonce();
    const url = buildConnectUrl({
      scheme: this.scheme,
      httpsPrefix: this.httpsPrefix,
      chain: this.chain,
      redirectUrl: this.redirectUrl,
      dappInfo,
      dappPublicKey: dapp.publicKey,
      nonce,
    });
    this.setPending({ kind: 'connect', nonceB64: b64uEncode(nonce) });
    this.navigate(url);
  }

  /**
   * Build the `connect` deep-link URL WITHOUT navigating or persisting pending
   * state — diagnostics/preview only (the real flow is {@link connect}). Uses
   * the persisted dApp keypair so `dappKey` matches a real connect; the nonce is
   * fresh each call. Lets a debug overlay show + test the exact URL on a phone.
   */
  previewConnectUrl(dappInfo: DappInfo): string {
    const dapp = this.ensureDappKeyPair();
    return buildConnectUrl({
      scheme: this.scheme,
      httpsPrefix: this.httpsPrefix,
      chain: this.chain,
      redirectUrl: this.redirectUrl,
      dappInfo,
      dappPublicKey: dapp.publicKey,
      nonce: randomNonce(),
    });
  }

  /**
   * Start a `signTx`: navigates to the wallet. Requires a prior connected
   * session. The witness set is delivered by `resume()` on the redirect back.
   */
  async signTx(opts: SignTxOptions): Promise<void> {
    const session = this.getSession();
    if (!session) throw new Error('not connected — call connect() first');
    const dapp = this.ensureDappKeyPair();

    const commit = opts.commit
      ? b64uDecode(opts.commit)
      : hexToBytes(this.requireTxHash(opts.tx));
    if (commit.length !== 32) {
      throw new Error(`commit must be 32 bytes (got ${commit.length})`);
    }
    const commitHex = bytesToHex(commit);

    const url = buildSignTxUrl({
      scheme: this.scheme,
      httpsPrefix: this.httpsPrefix,
      redirectUrl: this.redirectUrl,
      dappPublicKey: dapp.publicKey,
      dappSecretKey: dapp.secretKey,
      walletPublicKey: b64uDecode(session.walletKey),
      commit,
      payload: {
        session: session.session,
        // sdk-legacy: hex CBOR. spec (CIP-0186): base64url(CBOR).
        tx: this.signFormat === 'spec' ? b64uEncode(hexToBytes(opts.tx)) : opts.tx,
        partialSign: opts.partialSign ?? true,
        vkeyHints: opts.vkeyHints ?? [],
      },
      nonce: randomNonce(),
      ttl: this.nowSeconds() + (opts.ttlSeconds ?? 600),
    });
    this.setPending({ kind: 'signTx', commitHex });
    this.navigate(url);
  }

  /**
   * Recover a pending wallet response after the redirect. Pass the response URL
   * (defaults to `location.href`). Returns the connect session or signTx result,
   * or null when there is no pending response. Throws DeepLinkRejection if the
   * wallet rejected, or an Error on a decryption/verification failure.
   */
  async resume(responseUrl?: string): Promise<ResumeResult> {
    const url = responseUrl ?? this.currentUrl();
    const pendingRaw = this.storage.getItem(this.kPending);
    if (!url || !pendingRaw || !isResponseUrl(url)) return null;
    const pending = JSON.parse(pendingRaw) as Pending;
    const dapp = this.ensureDappKeyPair();

    try {
      if (pending.kind === 'connect') {
        const session = decodeConnectResponse({
          responseUrl: url,
          dappSecretKey: dapp.secretKey,
          expectedNonce: b64uDecode(pending.nonceB64),
        });
        this.storage.setItem(this.kSession, JSON.stringify(session));
        return { kind: 'connect', session };
      }
      const session = this.getSession();
      if (!session) throw new Error('signTx response with no stored session');
      const { witnessSet, signatureValid, txHash } = decodeSignTxResponse({
        responseUrl: url,
        dappSecretKey: dapp.secretKey,
        session,
        format: this.signFormat,
        expectedCommit: hexToBytes(pending.commitHex),
      });
      if (!signatureValid) {
        throw new Error('wallet response signature did not verify');
      }
      return {
        kind: 'signTx',
        // Prefer the spec envelope's txHash; for sdk-legacy it's the request
        // commit (= the tx hash the wallet bound to).
        result: { witnessSet, txHash: txHash ?? pending.commitHex, signatureValid },
      };
    } finally {
      this.storage.removeItem(this.kPending);
      this.clearResponseFromUrl();
    }
  }

  /**
   * Splice a witness set into a transaction. The SDK stays dependency-light, so
   * supply an assembler (e.g. MeshJS, Lucid, or CSL) — or send `{ txCbor,
   * witnessSet }` to your backend to assemble + submit (what the Aegis demo
   * does). Without one, this throws with guidance.
   */
  assemble(_txCbor: string, _witnessSetCbor: string): string {
    throw new Error(
      'assemble() needs a serialization library. Either assemble server-side ' +
        '(POST { txCbor, witnessSet } to your submit endpoint), or splice ' +
        'client-side with MeshJS/CSL. See the Aegis demo under examples/.',
    );
  }

  // --- internals ---

  private requireTxHash(txCbor: string): string {
    if (!this.resolveTxHash) {
      throw new Error(
        'no `resolveTxHash` configured and no `commit` passed — wire your tx ' +
          "builder's hash (MeshJS `resolveTxHash`, Lucid, or CSL " +
          '`hash_transaction`) in DeepLinkClientOptions, or pass `commit`.',
      );
    }
    return this.resolveTxHash(txCbor);
  }

  private ensureDappKeyPair(): { publicKey: Uint8Array; secretKey: Uint8Array } {
    const stored = this.storage.getItem(this.kDappKey);
    if (stored) return boxKeyPairFromSecret(b64uDecode(stored));
    const kp = newBoxKeyPair();
    this.storage.setItem(this.kDappKey, b64uEncode(kp.secretKey));
    return kp;
  }

  private setPending(p: Pending): void {
    this.storage.setItem(this.kPending, JSON.stringify(p));
  }

  private currentUrl(): string | undefined {
    return (globalThis as { location?: Location }).location?.href;
  }

  private clearResponseFromUrl(): void {
    const g = globalThis as {
      history?: History;
      location?: Location;
    };
    if (g.history?.replaceState && g.location) {
      g.history.replaceState(null, '', g.location.pathname);
    }
  }
}
