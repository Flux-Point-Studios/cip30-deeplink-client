// Pure verification core for the CIP-30-DeepLink inspector ("jwt.io for
// CIP-186"). DOM-free and fully unit-testable: it produces a per-step report of
// the SAME checks the shipped decoder runs, but WITHOUT short-circuiting — so a
// developer sees every step (method tag, payload decrypt, signature, echo), not
// just the first failure. `inspector.ts` renders this; tests assert its verdict
// matches `decodeConnectResponse` byte-for-byte.
import { b64uDecode, b64uEncode, utf8Decode, utf8Encode } from '../src/base64url.js';
import { canonicalSubject, canonicalSubjectCandidates } from '../src/canonical.js';
import {
  boxKeyPairFromSecret,
  boxOpen,
  boxSeal,
  bytesEqual,
  verifyEd25519,
} from '../src/crypto.js';
import { buildConnectUrl } from '../src/protocol.js';
import nacl from 'tweetnacl';

export type StepStatus = 'pass' | 'fail' | 'skip' | 'info';

export interface Step {
  label: string;
  status: StepStatus;
  detail: string;
  /** Spec error code this step gates on failure, if any. */
  code?: number;
}

export interface ConnectReport {
  /** accept = a conforming dApp seats the session; reject = the dApp throws;
   *  wallet-rejected = the wallet itself returned response=rejected. */
  verdict: 'accept' | 'reject' | 'wallet-rejected';
  /** The spec error code a conforming dApp surfaces (first failing step). */
  errorCode: number | null;
  steps: Step[];
  /** The canonical subject the wallet signed (signature-stripped), if derivable. */
  canonicalSubject: string | null;
  /** The decrypted session JSON, if the dApp secret was supplied + decrypt ok. */
  session: Record<string, unknown> | null;
}

export interface InspectInput {
  responseUrl: string;
  /** dApp X25519 secret — required to decrypt a connect payload (first contact). */
  dappSecretKey?: Uint8Array;
  /** The 24-byte nonce the dApp put in the matching connect request. */
  expectedNonce?: Uint8Array;
}

function paramsOf(url: string): URLSearchParams {
  return new URL(url).searchParams;
}

/**
 * Inspect a `connect` response URL step-by-step. Mirrors
 * `decodeConnectResponse`'s order (method → signature/echo presence → decrypt →
 * verify signature against the signingPublicKey INSIDE the payload → echo), but
 * evaluates every step so the report is complete. The overall `verdict`/
 * `errorCode` is decided by the FIRST failing step, exactly as the decoder.
 */
export function inspectConnectResponse(input: InspectInput): ConnectReport {
  const steps: Step[] = [];
  let canonical: string | null = null;
  let session: Record<string, unknown> | null = null;

  let params: URLSearchParams;
  try {
    params = paramsOf(input.responseUrl);
  } catch {
    return {
      verdict: 'reject',
      errorCode: null,
      steps: [{ label: 'Parse URL', status: 'fail', detail: 'not a valid URL' }],
      canonicalSubject: null,
      session: null,
    };
  }

  // 0. Wallet rejection envelope short-circuits everything.
  if (params.get('response') === 'rejected') {
    const code = Number(params.get('errorCode') ?? 'NaN');
    return {
      verdict: 'wallet-rejected',
      errorCode: Number.isNaN(code) ? null : code,
      steps: [
        {
          label: 'Response type',
          status: 'info',
          detail: `wallet rejected: errorCode=${params.get('errorCode')} "${params.get('errorMessage') ?? ''}"`,
          code: Number.isNaN(code) ? undefined : code,
        },
      ],
      canonicalSubject: null,
      session: null,
    };
  }

  steps.push({
    label: 'Response type',
    status: params.get('response') === 'approved' ? 'pass' : 'fail',
    detail: `response=${params.get('response') ?? '(missing)'}`,
  });

  // 1. Domain-separation method tag.
  const method = params.get('method');
  steps.push({
    label: 'Method tag (domain separation)',
    status: method === 'connect' ? 'pass' : 'fail',
    detail: method === 'connect' ? 'method=connect' : `method=${method ?? '(missing)'} — must be "connect"`,
    code: method === 'connect' ? undefined : -10,
  });

  // 2. Required signed-handshake parameters.
  const walletKeyB64 = params.get('walletKey');
  const nonceB64 = params.get('nonce');
  const payloadB64 = params.get('payload');
  const signatureB64 = params.get('signature');
  const echoB64 = params.get('echo');
  const missing = [
    ['walletKey', walletKeyB64],
    ['nonce', nonceB64],
    ['payload', payloadB64],
    ['signature', signatureB64],
    ['echo', echoB64],
  ].filter(([, v]) => !v).map(([k]) => k as string);
  steps.push({
    label: 'Required parameters present',
    status: missing.length === 0 ? 'pass' : 'fail',
    detail: missing.length === 0 ? 'walletKey, nonce, payload, echo, signature all present' : `missing: ${missing.join(', ')}`,
    code: missing.length === 0 ? undefined : -10,
  });

  // 3. Decrypt the session payload (needs the dApp secret).
  let signingPublicKey: Uint8Array | null = null;
  if (!input.dappSecretKey) {
    steps.push({
      label: 'Decrypt session payload',
      status: 'skip',
      detail: 'supply the dApp X25519 secret to decrypt + verify the signature',
    });
  } else if (!walletKeyB64 || !payloadB64 || !nonceB64) {
    steps.push({ label: 'Decrypt session payload', status: 'skip', detail: 'cannot decrypt — walletKey/nonce/payload missing' });
  } else {
    let plain: Uint8Array | null = null;
    try {
      plain = boxOpen(b64uDecode(payloadB64), b64uDecode(nonceB64), b64uDecode(walletKeyB64), input.dappSecretKey);
    } catch {
      plain = null;
    }
    if (!plain) {
      steps.push({ label: 'Decrypt session payload', status: 'fail', detail: 'NaCl box open failed (wrong key / corrupt ciphertext)', code: -7 });
    } else {
      try {
        session = JSON.parse(utf8Decode(plain)) as Record<string, unknown>;
        const spk = session['signingPublicKey'];
        signingPublicKey = typeof spk === 'string' ? b64uDecode(spk) : null;
        steps.push({
          label: 'Decrypt session payload',
          status: 'pass',
          detail: `session for walletId="${session['walletId']}", chain="${session['chain']}", expiresAt=${session['expiresAt']}`,
        });
      } catch {
        steps.push({ label: 'Decrypt session payload', status: 'fail', detail: 'decrypted payload is not valid session JSON', code: -7 });
      }
    }
  }

  // 4. Verify the Ed25519 signature over the canonical subject.
  try {
    canonical = canonicalSubject(input.responseUrl);
  } catch {
    canonical = null;
  }
  if (!signatureB64) {
    steps.push({ label: 'Response signature (Ed25519)', status: 'fail', detail: 'no signature parameter', code: -10 });
  } else if (!signingPublicKey) {
    steps.push({
      label: 'Response signature (Ed25519)',
      status: input.dappSecretKey ? 'fail' : 'skip',
      detail: input.dappSecretKey ? 'cannot verify — signingPublicKey unavailable (decrypt failed)' : 'needs the decrypted signingPublicKey (supply the dApp secret)',
    });
  } else {
    const sig = b64uDecode(signatureB64);
    const ok = canonicalSubjectCandidates(input.responseUrl).some((s) => verifyEd25519(utf8Encode(s), sig, signingPublicKey!));
    steps.push({
      label: 'Response signature (Ed25519)',
      status: ok ? 'pass' : 'fail',
      detail: ok ? 'verified against the session signingPublicKey' : 'signature does NOT verify against signingPublicKey',
      code: ok ? undefined : -10,
    });
  }

  // 5. Nonce echo (replay binding).
  if (!input.expectedNonce) {
    steps.push({ label: 'Nonce echo (replay binding)', status: 'skip', detail: 'supply the request nonce to check echo' });
  } else if (!echoB64) {
    steps.push({ label: 'Nonce echo (replay binding)', status: 'fail', detail: 'no echo parameter', code: -10 });
  } else {
    let ok = false;
    try {
      ok = bytesEqual(b64uDecode(echoB64), input.expectedNonce);
    } catch {
      ok = false;
    }
    steps.push({
      label: 'Nonce echo (replay binding)',
      status: ok ? 'pass' : 'fail',
      detail: ok ? 'echo equals the request nonce' : 'echo does NOT equal the request nonce — replay/foreign response',
      code: ok ? undefined : -5,
    });
  }

  const firstFail = steps.find((s) => s.status === 'fail');
  return {
    verdict: firstFail ? 'reject' : 'accept',
    errorCode: firstFail?.code ?? null,
    steps,
    canonicalSubject: canonical,
    session,
  };
}

// --- Helpers for the interactive loop (request builder + reference wallet) ---

export interface BuiltRequest {
  url: string;
  dappSecretKey: Uint8Array;
  dappPublicKey: Uint8Array;
  nonce: Uint8Array;
}

/** Build a connect request with a caller-supplied (or fixed) dApp key + nonce,
 *  returning the secret + nonce so the response can later be decrypted/checked. */
export function buildConnectRequest(opts: {
  dappSecretKey: Uint8Array;
  nonce: Uint8Array;
  redirectUrl: string;
  chain?: string;
  walletId?: string;
  dappName?: string;
  dappUrl?: string;
}): BuiltRequest {
  const kp = boxKeyPairFromSecret(opts.dappSecretKey);
  const url = buildConnectUrl({
    scheme: `cip30dl-${opts.walletId ?? 'wallet'}`,
    chain: opts.chain ?? 'cardano:preprod',
    redirectUrl: opts.redirectUrl,
    dappInfo: { name: opts.dappName ?? 'Inspector', url: opts.dappUrl ?? opts.redirectUrl },
    dappPublicKey: kp.publicKey,
    nonce: opts.nonce,
  });
  return { url, dappSecretKey: opts.dappSecretKey, dappPublicKey: kp.publicKey, nonce: opts.nonce };
}

export interface RefWalletKeys {
  boxSecret: Uint8Array; // 32-byte X25519
  signSeed: Uint8Array; // 32-byte Ed25519 seed
  responseNonce: Uint8Array; // 24-byte box nonce
}

export type ResponseFlaw = 'none' | 'echoMismatch' | 'tamperSignature' | 'unsigned';

/**
 * A reference conforming wallet: given a connect REQUEST URL, produce a signed
 * connect RESPONSE the dApp must accept (or, with `flaw`, a deliberately broken
 * one so a developer can SEE each failure mode go red).
 */
export function simulateConnectResponse(
  requestUrl: string,
  keys: RefWalletKeys,
  flaw: ResponseFlaw = 'none',
): string {
  const rp = paramsOf(requestUrl);
  const dappPub = b64uDecode(rp.get('dappKey')!);
  const reqNonce = rp.get('nonce')!;
  const redirect = decodeURIComponent(rp.get('redirect')!);
  const chain = decodeURIComponent(rp.get('chain') ?? 'cardano:preprod');
  const walletSign = nacl.sign.keyPair.fromSeed(keys.signSeed);
  const walletBox = boxKeyPairFromSecret(keys.boxSecret);

  const sessionJson = JSON.stringify({
    session: b64uEncode(nacl.hash(keys.boxSecret).subarray(0, 32)),
    network: chain === 'cardano:mainnet' ? 1 : 0,
    addresses: ['addr_test1qzinspector00000000000000000000000000000000000000000000000000000000000000000'],
    chain,
    walletId: rp.get('redirect') ? 'wallet' : 'wallet',
    expiresAt: 1900000000,
    signingPublicKey: b64uEncode(walletSign.publicKey),
  });
  const cipher = boxSeal(utf8Encode(sessionJson), keys.responseNonce, dappPub, keys.boxSecret);
  const echo = flaw === 'echoMismatch' ? b64uEncode(new Uint8Array(24).fill(0x5a)) : reqNonce;

  if (flaw === 'unsigned') {
    return (
      `${redirect}?response=approved` +
      `&walletKey=${b64uEncode(walletBox.publicKey)}` +
      `&nonce=${b64uEncode(keys.responseNonce)}` +
      `&payload=${b64uEncode(cipher)}`
    );
  }

  const base =
    `${redirect}?response=approved` +
    `&method=connect` +
    `&walletKey=${b64uEncode(walletBox.publicKey)}` +
    `&nonce=${b64uEncode(keys.responseNonce)}` +
    `&echo=${echo}` +
    `&payload=${b64uEncode(cipher)}`;
  const sig =
    flaw === 'tamperSignature'
      ? new Uint8Array(64).fill(0x07)
      : nacl.sign.detached(utf8Encode(canonicalSubject(base)), walletSign.secretKey);
  return `${base}&signature=${b64uEncode(sig)}`;
}
