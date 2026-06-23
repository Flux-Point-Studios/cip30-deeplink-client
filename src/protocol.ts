// Pure CIP-30-DeepLink wire helpers: build request URLs and decode/verify
// response URLs. No I/O, no navigation, no storage — every function is a pure
// transform, so the round-trip can be unit-tested against the wallet crypto.

import {
  b64uDecode,
  b64uEncode,
  b64uEncodeText,
  utf8Decode,
  utf8Encode,
} from './base64url.js';
import { canonicalSubjectCandidates } from './canonical.js';
import { boxOpen, boxSeal, verifyEd25519 } from './crypto.js';
import {
  DeepLinkRejection,
  type DappInfo,
  type Session,
  type SignFormat,
} from './types.js';

export const PROTOCOL_VERSION = '1';

/** The deep-link scheme for a wallet id, e.g. `yuti` -> `cip30dl-yuti`. */
export const walletScheme = (walletId: string): string => `cip30dl-${walletId}`;

/**
 * The request-URL base up to (but excluding) the method name (`connect` /
 * `signTx`). Prefer the wallet's https universal-link prefix when it advertises
 * one — iOS Safari opens universal links reliably but frequently drops
 * custom-scheme (`cip30dl-<id>:`) navigations silently — else fall back to the
 * custom scheme. Both forms carry identical query params (spec Appendix C.1).
 *   - https:  `https://cip30dl.wallet.io/cip30dl/v1/` + `connect`
 *   - scheme: `cip30dl-<id>:/v1/` + `connect`
 */
export const endpointBase = (scheme: string, httpsPrefix?: string): string =>
  httpsPrefix && httpsPrefix.length > 0 ? httpsPrefix : `${scheme}:/v1/`;

export function hexToBytes(hex: string): Uint8Array {
  if (hex.length % 2 !== 0) throw new Error('odd-length hex string');
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    const byte = Number.parseInt(hex.substr(i * 2, 2), 16);
    if (Number.isNaN(byte)) throw new Error('invalid hex string');
    out[i] = byte;
  }
  return out;
}

export function bytesToHex(bytes: Uint8Array): string {
  let s = '';
  for (const b of bytes) s += b.toString(16).padStart(2, '0');
  return s;
}

export interface ConnectUrlParams {
  scheme: string;
  /** Optional https universal-link prefix (e.g. `https://cip30dl.wallet.io/cip30dl/v1/`).
   *  When set, the request uses the https form instead of the custom scheme. */
  httpsPrefix?: string;
  chain: string;
  redirectUrl: string;
  dappInfo: DappInfo;
  dappPublicKey: Uint8Array;
  nonce: Uint8Array; // 24 bytes
}

/** Build the `connect` deep-link URL (spec §connect). */
export function buildConnectUrl(p: ConnectUrlParams): string {
  const info = b64uEncodeText(
    JSON.stringify({
      name: p.dappInfo.name,
      url: p.dappInfo.url,
      ...(p.dappInfo.iconUrl ? { iconUrl: p.dappInfo.iconUrl } : {}),
    }),
  );
  return (
    `${endpointBase(p.scheme, p.httpsPrefix)}connect?v=${PROTOCOL_VERSION}` +
    `&dapp=${info}` +
    `&dappKey=${b64uEncode(p.dappPublicKey)}` +
    `&redirect=${encodeURIComponent(p.redirectUrl)}` +
    `&chain=${encodeURIComponent(p.chain)}` +
    `&nonce=${b64uEncode(p.nonce)}`
  );
}

export interface SignTxUrlParams {
  scheme: string;
  /** Optional https universal-link prefix — see {@link ConnectUrlParams.httpsPrefix}. */
  httpsPrefix?: string;
  redirectUrl: string;
  dappPublicKey: Uint8Array;
  dappSecretKey: Uint8Array;
  /** The wallet's connect-time X25519 public key (`session.walletKey`). */
  walletPublicKey: Uint8Array;
  /** 32-byte commit = BLAKE2b-256(tx_body) = the tx hash. */
  commit: Uint8Array;
  /** The signTx payload object: { session, tx, partialSign, vkeyHints }. */
  payload: Record<string, unknown>;
  nonce: Uint8Array; // 24 bytes
  /** Absolute unix-seconds ttl. */
  ttl: number;
}

/** Build the `signTx` deep-link URL with a NaCl-box-encrypted payload. */
export function buildSignTxUrl(p: SignTxUrlParams): string {
  const plaintext = utf8Encode(JSON.stringify(p.payload));
  const cipher = boxSeal(plaintext, p.nonce, p.walletPublicKey, p.dappSecretKey);
  return (
    `${endpointBase(p.scheme, p.httpsPrefix)}signTx?v=${PROTOCOL_VERSION}` +
    `&dappKey=${b64uEncode(p.dappPublicKey)}` +
    `&redirect=${encodeURIComponent(p.redirectUrl)}` +
    `&nonce=${b64uEncode(p.nonce)}` +
    `&commit=${b64uEncode(p.commit)}` +
    `&ttl=${p.ttl}` +
    `&payload=${b64uEncode(cipher)}`
  );
}

/** True if `url` carries a wallet response (`response=...`). */
export function isResponseUrl(url: string): boolean {
  try {
    return new URL(url).searchParams.has('response');
  } catch {
    return false;
  }
}

function paramsOf(url: string): URLSearchParams {
  return new URL(url).searchParams;
}

/** Throws DeepLinkRejection if the response is a wallet rejection. */
export function throwIfRejected(params: URLSearchParams): void {
  if (params.get('response') === 'rejected') {
    throw new DeepLinkRejection(
      Number(params.get('errorCode') ?? 'NaN'),
      params.get('errorMessage') ?? '',
    );
  }
}

/** Decode + adopt a `connect` response into a Session (throws on rejection). */
export function decodeConnectResponse(args: {
  responseUrl: string;
  dappSecretKey: Uint8Array;
}): Session {
  const params = paramsOf(args.responseUrl);
  throwIfRejected(params);
  const walletKeyB64 = params.get('walletKey');
  const payloadB64 = params.get('payload');
  const nonceB64 = params.get('nonce');
  if (!walletKeyB64 || !payloadB64 || !nonceB64) {
    throw new Error('connect response missing walletKey/payload/nonce');
  }
  const plaintext = boxOpen(
    b64uDecode(payloadB64),
    b64uDecode(nonceB64),
    b64uDecode(walletKeyB64),
    args.dappSecretKey,
  );
  if (!plaintext) throw new Error('connect response decryption failed');
  const json = JSON.parse(utf8Decode(plaintext)) as Omit<Session, 'walletKey'>;
  return { ...json, walletKey: walletKeyB64 };
}

/**
 * Decode a `signTx` response: decrypt the witness set and verify the wallet's
 * Ed25519 response signature against the canonical subject. Throws on rejection
 * or decryption failure; returns the witness with a `signatureValid` flag.
 */
export function decodeSignTxResponse(args: {
  responseUrl: string;
  dappSecretKey: Uint8Array;
  session: Session;
  /** Wire format of the wallet's reply (default `sdk-legacy`). */
  format?: SignFormat;
  /** The 32-byte request commit — REQUIRED under `spec` to verify the echo. */
  expectedCommit?: Uint8Array;
}): { witnessSet: string; signatureValid: boolean; txHash?: string } {
  const params = paramsOf(args.responseUrl);
  throwIfRejected(params);
  const payloadB64 = params.get('payload');
  const nonceB64 = params.get('nonce');
  const signatureB64 = params.get('signature');
  if (!payloadB64 || !nonceB64 || !signatureB64) {
    throw new Error('signTx response missing payload/nonce/signature');
  }
  const plain = boxOpen(
    b64uDecode(payloadB64),
    b64uDecode(nonceB64),
    b64uDecode(args.session.walletKey),
    args.dappSecretKey,
  );
  if (!plain) throw new Error('signTx response decryption failed');
  const signature = b64uDecode(signatureB64);
  const signingPublicKey = b64uDecode(args.session.signingPublicKey);
  const signatureValid = canonicalSubjectCandidates(args.responseUrl).some(
    (subject) => verifyEd25519(utf8Encode(subject), signature, signingPublicKey),
  );

  if (args.format === 'spec') {
    // CIP-0186 envelope: { commit, witnessSet, txHash } (all base64url).
    let env: { commit?: string; witnessSet?: string; txHash?: string };
    try {
      env = JSON.parse(utf8Decode(plain)) as typeof env;
    } catch {
      throw new Error('spec signTx response payload is not the JSON envelope');
    }
    if (!env.witnessSet || !env.commit) {
      throw new Error('spec signTx response missing commit/witnessSet');
    }
    // MUST verify the commit echo (defeats tx-body substitution across the
    // request/response loop): mismatch ⇒ errorCode -2 CommitMismatch.
    if (args.expectedCommit && env.commit !== b64uEncode(args.expectedCommit)) {
      throw new DeepLinkRejection(-2, 'commit mismatch');
    }
    return {
      witnessSet: bytesToHex(b64uDecode(env.witnessSet)),
      signatureValid,
      txHash: env.txHash,
    };
  }
  // sdk-legacy: the decrypted payload IS the raw transaction_witness_set CBOR.
  return { witnessSet: bytesToHex(plain), signatureValid };
}
