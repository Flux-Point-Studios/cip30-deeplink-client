// The inspector's per-step core must reach the SAME verdict + error code as the
// shipped decoder on every case — otherwise the playground would teach the wrong
// thing. Drives a fixed-key request → reference-wallet response (clean + each
// flaw) through both inspectConnectResponse and decodeConnectResponse.
import { describe, expect, it } from 'vitest';
import {
  buildConnectRequest,
  inspectConnectResponse,
  simulateConnectResponse,
  type ResponseFlaw,
} from '../playground/inspect-core.js';
import { decodeConnectResponse } from '../src/protocol.js';
import { DeepLinkRejection } from '../src/types.js';

const REDIRECT = 'https://aegis.example/cb';
const dappSecret = new Uint8Array(32).fill(1);
const nonce = new Uint8Array(24).fill(4);
const refKeys = {
  boxSecret: new Uint8Array(32).fill(2),
  signSeed: new Uint8Array(32).fill(3),
  responseNonce: new Uint8Array(24).fill(5),
};

function decoderVerdict(url: string): { verdict: string; code: number | null } {
  try {
    decodeConnectResponse({ responseUrl: url, dappSecretKey: dappSecret, expectedNonce: nonce });
    return { verdict: 'accept', code: null };
  } catch (e) {
    if (e instanceof DeepLinkRejection) return { verdict: 'reject', code: e.errorCode };
    return { verdict: 'reject', code: null }; // structural Error (e.g. decrypt failed)
  }
}

const CASES: Array<{ flaw: ResponseFlaw; verdict: string; code: number | null }> = [
  { flaw: 'none', verdict: 'accept', code: null },
  { flaw: 'echoMismatch', verdict: 'reject', code: -5 },
  { flaw: 'tamperSignature', verdict: 'reject', code: -10 },
  { flaw: 'unsigned', verdict: 'reject', code: -10 },
];

describe('inspector core is faithful to the shipped decoder', () => {
  const req = buildConnectRequest({ dappSecretKey: dappSecret, nonce, redirectUrl: REDIRECT });

  for (const c of CASES) {
    it(`${c.flaw}: inspector verdict matches decoder (${c.verdict}${c.code ?? ''})`, () => {
      const url = simulateConnectResponse(req.url, refKeys, c.flaw);
      const report = inspectConnectResponse({ responseUrl: url, dappSecretKey: dappSecret, expectedNonce: nonce });
      const decoder = decoderVerdict(url);

      // Inspector matches the stated expectation...
      expect(report.verdict).toBe(c.verdict);
      if (c.code !== null) expect(report.errorCode).toBe(c.code);
      // ...AND matches the shipped decoder (the load-bearing invariant).
      expect(report.verdict).toBe(decoder.verdict === 'accept' ? 'accept' : 'reject');
      if (decoder.code !== null) expect(report.errorCode).toBe(decoder.code);
    });
  }

  it('valid case decrypts the session and yields a canonical subject', () => {
    const url = simulateConnectResponse(req.url, refKeys, 'none');
    const report = inspectConnectResponse({ responseUrl: url, dappSecretKey: dappSecret, expectedNonce: nonce });
    expect(report.session?.walletId).toBeDefined();
    expect(report.canonicalSubject?.startsWith('cip30dl-v1\n')).toBe(true);
    expect(report.steps.every((s) => s.status !== 'fail')).toBe(true);
  });

  it('without the dApp secret, decrypt + signature steps are skipped (not failed)', () => {
    const url = simulateConnectResponse(req.url, refKeys, 'none');
    const report = inspectConnectResponse({ responseUrl: url });
    const decrypt = report.steps.find((s) => s.label === 'Decrypt session payload');
    const sig = report.steps.find((s) => s.label === 'Response signature (Ed25519)');
    expect(decrypt?.status).toBe('skip');
    expect(sig?.status).toBe('skip');
  });
});
