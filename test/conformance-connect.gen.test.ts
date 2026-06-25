// Generates a REAL known-answer vector for the hardened (signed) connect
// handshake and self-verifies it against the shipped SDK decoder. Run:
//   npx vitest run test/conformance-connect.gen.test.ts
// Emits conformance/connect-kat.json (rich, for wallet authors) and
// conformance/spec-vector-canonical-connect.json (a CIP-0186 tests/vectors entry).
//
// All inputs are FIXED (no randomness) so any implementation that plugs in the
// same keys/nonces MUST reproduce the same canonical subject, signature, and URL.
import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import nacl from 'tweetnacl';
import { describe, expect, it } from 'vitest';
import { b64uDecode, b64uEncode, utf8Encode } from '../src/base64url.js';
import { canonicalSubject } from '../src/canonical.js';
import { boxSeal } from '../src/crypto.js';
import { decodeConnectResponse, decodeSignTxResponse } from '../src/protocol.js';
import { DeepLinkRejection } from '../src/types.js';

const REDIRECT = 'https://aegis.example/cb';

// Fixed test material (deterministic — NOT secret, NOT for production).
const dappBoxSecret = new Uint8Array(32).fill(1); // dApp X25519 secret
const walletBoxSecret = new Uint8Array(32).fill(2); // wallet X25519 secret
const walletSignSeed = new Uint8Array(32).fill(3); // wallet Ed25519 seed
const requestNonce = new Uint8Array(24).fill(4); // dApp's connect-request nonce
const responseNonce = new Uint8Array(24).fill(5); // wallet's NaCl-box nonce

const dappBox = nacl.box.keyPair.fromSecretKey(dappBoxSecret);
const walletBox = nacl.box.keyPair.fromSecretKey(walletBoxSecret);
const walletSign = nacl.sign.keyPair.fromSeed(walletSignSeed);

const sessionJson = {
  session: 'c2Vzc2lvbi1pZC1jb25uZWN0LWthdC0wMDAwMDAwMDAwMDAwMDA',
  network: 0,
  addresses: ['addr_test1qzconnectkatexampleaddr00000000000000000000000000000000000000000000000000000'],
  chain: 'cardano:preprod',
  walletId: 'lace',
  expiresAt: 1810000000,
  signingPublicKey: b64uEncode(walletSign.publicKey),
};

/** A conforming wallet's signed connect response, built deterministically. */
function buildSignedConnect(echoB64: string): string {
  const cipher = boxSeal(
    utf8Encode(JSON.stringify(sessionJson)),
    responseNonce,
    dappBox.publicKey,
    walletBoxSecret,
  );
  const base =
    `${REDIRECT}?response=approved` +
    `&method=connect` +
    `&walletKey=${b64uEncode(walletBox.publicKey)}` +
    `&nonce=${b64uEncode(responseNonce)}` +
    `&echo=${echoB64}` +
    `&payload=${b64uEncode(cipher)}`;
  const sig = nacl.sign.detached(utf8Encode(canonicalSubject(base)), walletSign.secretKey);
  return `${base}&signature=${b64uEncode(sig)}`;
}

describe('CIP-0186 signed-connect known-answer vector (self-verified vs the SDK)', () => {
  const validUrl = buildSignedConnect(b64uEncode(requestNonce));

  it('VALID: the shipped decoder accepts the signed connect and adopts the session', () => {
    const session = decodeConnectResponse({
      responseUrl: validUrl,
      dappSecretKey: dappBoxSecret,
      expectedNonce: requestNonce,
    });
    expect(session.session).toBe(sessionJson.session);
    expect(session.signingPublicKey).toBe(b64uEncode(walletSign.publicKey));
    expect(session.walletKey).toBe(b64uEncode(walletBox.publicKey));
  });

  it('REJECT -5: echo is a different nonce than the dApp sent (replay binding)', () => {
    // Wallet echoes a foreign nonce; signature still valid over that echo.
    const url = buildSignedConnect(b64uEncode(new Uint8Array(24).fill(9)));
    expect(() =>
      decodeConnectResponse({ responseUrl: url, dappSecretKey: dappBoxSecret, expectedNonce: requestNonce }),
    ).toThrow(DeepLinkRejection);
    try {
      decodeConnectResponse({ responseUrl: url, dappSecretKey: dappBoxSecret, expectedNonce: requestNonce });
    } catch (e) {
      expect((e as DeepLinkRejection).errorCode).toBe(-5);
    }
  });

  it('REJECT -10: signature tampered', () => {
    const tampered = validUrl.replace(/signature=[^&]+/, 'signature=' + b64uEncode(new Uint8Array(64).fill(7)));
    try {
      decodeConnectResponse({ responseUrl: tampered, dappSecretKey: dappBoxSecret, expectedNonce: requestNonce });
      expect.fail('should have thrown');
    } catch (e) {
      expect((e as DeepLinkRejection).errorCode).toBe(-10);
    }
  });

  it('REJECT -10: legacy/unsigned response (no method/echo/signature)', () => {
    const legacy = validUrl
      .replace('&method=connect', '')
      .replace(/&echo=[^&]+/, '')
      .replace(/&signature=[^&]+/, '');
    try {
      decodeConnectResponse({ responseUrl: legacy, dappSecretKey: dappBoxSecret, expectedNonce: requestNonce });
      expect.fail('should have thrown');
    } catch (e) {
      expect((e as DeepLinkRejection).errorCode).toBe(-10);
    }
  });

  it('method confusion: the signTx decoder refuses a connect reply', () => {
    expect(() =>
      decodeSignTxResponse({
        responseUrl: validUrl,
        dappSecretKey: dappBoxSecret,
        session: {
          session: sessionJson.session,
          network: 0,
          addresses: sessionJson.addresses,
          chain: 'cardano:preprod',
          walletId: 'lace',
          expiresAt: sessionJson.expiresAt,
          signingPublicKey: sessionJson.signingPublicKey,
          walletKey: b64uEncode(walletBox.publicKey),
        },
      }),
    ).toThrow(/method=connect/);
  });

  it('emits the KAT + the spec canonical_subject vector', () => {
    const canonical = canonicalSubject(validUrl);
    const params = (() => {
      const u = new URL(validUrl);
      const o: Record<string, string> = {};
      u.searchParams.forEach((v, k) => (o[k] = v));
      return o;
    })();

    const here = dirname(fileURLToPath(import.meta.url));
    const outDir = join(here, '..', 'conformance');
    mkdirSync(outDir, { recursive: true });

    const kat = {
      name: 'signed-connect known-answer vector (CIP-0186 §connect, hardened)',
      note: 'All inputs fixed and non-secret. The canonical subject and every non-signature field are byte-exact for any conforming wallet. The signature here is a DETERMINISTIC Ed25519 known answer (RFC 8032; tweetnacl/libsodium/pynacl reproduce it byte-for-byte). Implementations using RANDOMIZED/hedged Ed25519 (e.g. Apple CryptoKit, RFC 8032 §8.5) produce DIFFERENT but equally valid signature bytes — so conformance is "the signature VERIFIES against signingPublicKey", NOT "the bytes match this KAT". A conforming dApp MUST accept the valid case and reject the negatives.',
      inputs: {
        redirect: REDIRECT,
        dappX25519Secret_hex: Buffer.from(dappBoxSecret).toString('hex'),
        dappX25519Public_b64url: b64uEncode(dappBox.publicKey),
        walletX25519Secret_hex: Buffer.from(walletBoxSecret).toString('hex'),
        walletX25519Public_b64url: b64uEncode(walletBox.publicKey),
        walletEd25519Seed_hex: Buffer.from(walletSignSeed).toString('hex'),
        signingPublicKey_b64url: b64uEncode(walletSign.publicKey),
        requestNonce_b64url: b64uEncode(requestNonce),
        responseNonce_b64url: b64uEncode(responseNonce),
        sessionJson,
      },
      derived: {
        payload_b64url: params.payload,
        echo_b64url: params.echo,
        canonicalSubject_utf8: canonical,
        signature_b64url: new URL(validUrl).searchParams.get('signature'),
        responseUrl_valid: validUrl,
      },
      cases: [
        { case: 'valid', expect: 'accept', dapp_expectedNonce_b64url: b64uEncode(requestNonce) },
        { case: 'echo_mismatch', expect: 'reject', errorCode: -5, responseUrl: buildSignedConnect(b64uEncode(new Uint8Array(24).fill(9))) },
        { case: 'tampered_signature', expect: 'reject', errorCode: -10, responseUrl: validUrl.replace(/signature=[^&]+/, 'signature=' + b64uEncode(new Uint8Array(64).fill(7))) },
        { case: 'legacy_unsigned', expect: 'reject', errorCode: -10, responseUrl: validUrl.replace('&method=connect', '').replace(/&echo=[^&]+/, '').replace(/&signature=[^&]+/, '') },
      ],
    };
    writeFileSync(join(outDir, 'connect-kat.json'), JSON.stringify(kat, null, 2) + '\n');

    // CIP-0186 tests/vectors entry: canonical_subject category over the signed
    // connect response (proves the canonical form is well-defined with method+echo).
    const specVector = {
      name: 'canonical_subject: signed connect response (method + echo)',
      spec_section: 'Response signing; connect',
      category: 'canonical_subject',
      input: { emitted_url: validUrl },
      expected: { canonical_subject_utf8: canonical },
      should_reject: false,
      rejection_reason: null,
    };
    writeFileSync(join(outDir, 'spec-vector-canonical-connect.json'), JSON.stringify(specVector, null, 2) + '\n');

    expect(canonical.startsWith('cip30dl-v1\n')).toBe(true);
  });
});
