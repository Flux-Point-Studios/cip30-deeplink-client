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
import { canonicalSubject } from './canonical.js';
import { boxOpen, boxSeal, verifyEd25519 } from './crypto.js';
import { DeepLinkRejection, type DappInfo, type Session } from './types.js';

export const PROTOCOL_VERSION = '1';

/** The deep-link scheme for a wallet id, e.g. `yuti` -> `cip30dl-yuti`. */
export const walletScheme = (walletId: string): string => `cip30dl-${walletId}`;

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
    `${p.scheme}:/v1/connect?v=${PROTOCOL_VERSION}` +
    `&dapp=${info}` +
    `&dappKey=${b64uEncode(p.dappPublicKey)}` +
    `&redirect=${encodeURIComponent(p.redirectUrl)}` +
    `&chain=${encodeURIComponent(p.chain)}` +
    `&nonce=${b64uEncode(p.nonce)}`
  );
}

export interface SignTxUrlParams {
  scheme: string;
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
    `${p.scheme}:/v1/signTx?v=${PROTOCOL_VERSION}` +
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
}): { witnessSet: string; signatureValid: boolean } {
  const params = paramsOf(args.responseUrl);
  throwIfRejected(params);
  const payloadB64 = params.get('payload');
  const nonceB64 = params.get('nonce');
  const signatureB64 = params.get('signature');
  if (!payloadB64 || !nonceB64 || !signatureB64) {
    throw new Error('signTx response missing payload/nonce/signature');
  }
  const witness = boxOpen(
    b64uDecode(payloadB64),
    b64uDecode(nonceB64),
    b64uDecode(args.session.walletKey),
    args.dappSecretKey,
  );
  if (!witness) throw new Error('signTx response decryption failed');
  const signatureValid = verifyEd25519(
    utf8Encode(canonicalSubject(args.responseUrl)),
    b64uDecode(signatureB64),
    b64uDecode(args.session.signingPublicKey),
  );
  return { witnessSet: bytesToHex(witness), signatureValid };
}
