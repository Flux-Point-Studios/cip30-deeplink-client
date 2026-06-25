import nacl from 'tweetnacl';
import { describe, expect, it } from 'vitest';
import { b64uDecode, b64uEncode } from '../src/base64url.js';
import {
  buildConnectUrl,
  buildSignTxUrl,
  bytesToHex,
  decodeConnectResponse,
  decodeSignTxResponse,
} from '../src/protocol.js';
import { DeepLinkRejection, type Session } from '../src/types.js';
import { FakeYutiWallet, TEST_ADDRESS as ADDRESS } from './fake-wallet.js';

const SCHEME = 'cip30dl-yuti';
const REDIRECT = 'https://aegis.fluxpointstudios.com/cb';

/** Run a connect against the fake wallet; return the response URL and the exact
 *  request nonce the dApp would have persisted (needed for the echo check). */
function doConnect(
  dapp: nacl.BoxKeyPair,
  wallet: FakeYutiWallet,
  redirect: string,
): { responseUrl: string; nonce: Uint8Array } {
  const nonce = nacl.randomBytes(24);
  const responseUrl = wallet.handleConnect(
    buildConnectUrl({
      scheme: SCHEME,
      chain: 'cardano:preprod',
      redirectUrl: redirect,
      dappInfo: { name: 'Aegis', url: redirect },
      dappPublicKey: dapp.publicKey,
      nonce,
    }),
  );
  return { responseUrl, nonce };
}

/** Full connect round-trip → an adopted Session (fail-closed verification). */
function establishSession(
  dapp: nacl.BoxKeyPair,
  wallet: FakeYutiWallet,
  redirect: string,
): Session {
  const { responseUrl, nonce } = doConnect(dapp, wallet, redirect);
  return decodeConnectResponse({
    responseUrl,
    dappSecretKey: dapp.secretKey,
    expectedNonce: nonce,
  });
}

/** The wire errorCode of the DeepLinkRejection `fn` throws (fails if it doesn't). */
function rejectionCode(fn: () => unknown): number {
  try {
    fn();
  } catch (e) {
    if (e instanceof DeepLinkRejection) return e.errorCode;
    throw e;
  }
  throw new Error('expected a DeepLinkRejection, but nothing was thrown');
}

describe('connect + signTx round-trip against a Yuti-compatible wallet', () => {
  it('connect: dApp verifies the signed response and adopts walletKey', () => {
    const dapp = nacl.box.keyPair();
    const wallet = new FakeYutiWallet(REDIRECT);
    const { responseUrl, nonce } = doConnect(dapp, wallet, REDIRECT);
    const session = decodeConnectResponse({
      responseUrl,
      dappSecretKey: dapp.secretKey,
      expectedNonce: nonce,
    });

    expect(session.session).toBe(wallet.sessionId);
    expect(session.addresses[0]).toBe(ADDRESS);
    expect(session.chain).toBe('cardano:preprod');
    expect(session.network).toBe(0);
    expect(session.signingPublicKey).toBe(b64uEncode(wallet.sign.publicKey));
    expect(session.walletKey).toBe(b64uEncode(wallet.box.publicKey));
  });

  it('signTx: wallet decrypts the tx, dApp decrypts the witness + verifies the signature', () => {
    const dapp = nacl.box.keyPair();
    const wallet = new FakeYutiWallet(REDIRECT);
    const session = establishSession(dapp, wallet, REDIRECT);

    const tx = '84a40080018002000300a0f5f6';
    const signUrl = buildSignTxUrl({
      scheme: SCHEME,
      redirectUrl: REDIRECT,
      dappPublicKey: dapp.publicKey,
      dappSecretKey: dapp.secretKey,
      walletPublicKey: b64uDecode(session.walletKey),
      commit: new Uint8Array(32).fill(7),
      payload: { session: session.session, tx, partialSign: true, vkeyHints: [] },
      nonce: nacl.randomBytes(24),
      ttl: 1900000000,
    });

    const { responseUrl, requestTx } = wallet.handleSignTx(signUrl);
    expect(requestTx).toBe(tx); // the wallet saw exactly the tx we sent

    const result = decodeSignTxResponse({
      responseUrl,
      dappSecretKey: dapp.secretKey,
      session,
    });
    expect(result.signatureValid).toBe(true);
    expect(result.witnessSet).toBe(bytesToHex(wallet.witness));
  });

  it('signTx with a path-less (bare-origin) redirect still verifies (empty-path parity)', () => {
    // Regression for the canonical-subject path divergence: Yuti signs a
    // path-less redirect with NO slash (Dart Uri.path = ''); the SDK must
    // verify it even though WHATWG URL.pathname normalizes to '/'. The fake
    // wallet signs the Dart-style subject independently (fake-wallet.ts), so
    // this genuinely exercises cross-impl parity instead of masking it.
    const dapp = nacl.box.keyPair();
    const bare = 'https://aegis.fluxpointstudios.com'; // no path
    const wallet = new FakeYutiWallet(bare);
    const session = establishSession(dapp, wallet, bare);
    const signUrl = buildSignTxUrl({
      scheme: SCHEME,
      redirectUrl: bare,
      dappPublicKey: dapp.publicKey,
      dappSecretKey: dapp.secretKey,
      walletPublicKey: b64uDecode(session.walletKey),
      commit: new Uint8Array(32).fill(7),
      payload: { session: session.session, tx: '84a4', partialSign: true, vkeyHints: [] },
      nonce: nacl.randomBytes(24),
      ttl: 1900000000,
    });
    const { responseUrl } = wallet.handleSignTx(signUrl);
    const result = decodeSignTxResponse({ responseUrl, dappSecretKey: dapp.secretKey, session });
    expect(result.signatureValid).toBe(true);
  });

  it('signTx: a tampered response signature fails verification', () => {
    const dapp = nacl.box.keyPair();
    const wallet = new FakeYutiWallet(REDIRECT);
    const session = establishSession(dapp, wallet, REDIRECT);
    const signUrl = buildSignTxUrl({
      scheme: SCHEME,
      redirectUrl: REDIRECT,
      dappPublicKey: dapp.publicKey,
      dappSecretKey: dapp.secretKey,
      walletPublicKey: b64uDecode(session.walletKey),
      commit: new Uint8Array(32).fill(7),
      payload: { session: session.session, tx: '84a4', partialSign: true, vkeyHints: [] },
      nonce: nacl.randomBytes(24),
      ttl: 1900000000,
    });
    const { responseUrl } = wallet.handleSignTx(signUrl);
    // Flip the signature to a different (valid-length) value.
    const tampered = responseUrl.replace(
      /signature=[^&]+/,
      'signature=' + b64uEncode(new Uint8Array(64).fill(1)),
    );
    const result = decodeSignTxResponse({
      responseUrl: tampered,
      dappSecretKey: dapp.secretKey,
      session,
    });
    expect(result.signatureValid).toBe(false);
  });
});

describe('connect authentication (signed response + nonce echo)', () => {
  it('rejects a legacy/unsigned connect response (no method/echo/signature)', () => {
    // The pre-hardening wire shape — what an unauthenticated wallet would send.
    // Fail-closed: it must never seat a session.
    const dapp = nacl.box.keyPair();
    const wallet = new FakeYutiWallet(REDIRECT);
    const { responseUrl, nonce } = doConnect(dapp, wallet, REDIRECT);
    const legacy = responseUrl
      .replace('&method=connect', '')
      .replace(/&echo=[^&]+/, '')
      .replace(/&signature=[^&]+/, '');
    expect(
      rejectionCode(() =>
        decodeConnectResponse({
          responseUrl: legacy,
          dappSecretKey: dapp.secretKey,
          expectedNonce: nonce,
        }),
      ),
    ).toBe(-10);
  });

  it('rejects a connect response whose signature was tampered (-10)', () => {
    const dapp = nacl.box.keyPair();
    const wallet = new FakeYutiWallet(REDIRECT);
    const { responseUrl, nonce } = doConnect(dapp, wallet, REDIRECT);
    const tampered = responseUrl.replace(
      /signature=[^&]+/,
      'signature=' + b64uEncode(new Uint8Array(64).fill(9)),
    );
    expect(
      rejectionCode(() =>
        decodeConnectResponse({
          responseUrl: tampered,
          dappSecretKey: dapp.secretKey,
          expectedNonce: nonce,
        }),
      ),
    ).toBe(-10);
  });

  it('rejects a connect whose echoed nonce is not the one we sent (-5 replay)', () => {
    // The response is otherwise fully valid (signature covers the real echo);
    // only the client's expectation differs — i.e. a replayed/foreign reply.
    const dapp = nacl.box.keyPair();
    const wallet = new FakeYutiWallet(REDIRECT);
    const { responseUrl } = doConnect(dapp, wallet, REDIRECT);
    const someOtherNonce = nacl.randomBytes(24);
    expect(
      rejectionCode(() =>
        decodeConnectResponse({
          responseUrl,
          dappSecretKey: dapp.secretKey,
          expectedNonce: someOtherNonce,
        }),
      ),
    ).toBe(-5);
  });

  it('rejects a connect payload swapped under a still-valid request nonce', () => {
    // Tamper the ciphertext: box-open MAC fails before any session is adopted.
    const dapp = nacl.box.keyPair();
    const wallet = new FakeYutiWallet(REDIRECT);
    const { responseUrl, nonce } = doConnect(dapp, wallet, REDIRECT);
    const corrupted = responseUrl.replace(
      /payload=[^&]+/,
      'payload=' + b64uEncode(new Uint8Array(80).fill(3)),
    );
    expect(() =>
      decodeConnectResponse({
        responseUrl: corrupted,
        dappSecretKey: dapp.secretKey,
        expectedNonce: nonce,
      }),
    ).toThrow(/decryption failed/);
  });

  it('rejects a connect reply fed to the signTx decoder (method confusion)', () => {
    const dapp = nacl.box.keyPair();
    const wallet = new FakeYutiWallet(REDIRECT);
    const session = establishSession(dapp, wallet, REDIRECT);
    const { responseUrl } = doConnect(dapp, wallet, REDIRECT);
    expect(() =>
      decodeSignTxResponse({ responseUrl, dappSecretKey: dapp.secretKey, session }),
    ).toThrow(/method=connect/);
  });

  it('verifies a signed connect over a path-less redirect (empty-path parity)', () => {
    const dapp = nacl.box.keyPair();
    const bare = 'https://aegis.fluxpointstudios.com';
    const wallet = new FakeYutiWallet(bare);
    const session = establishSession(dapp, wallet, bare);
    expect(session.session).toBe(wallet.sessionId);
    expect(session.signingPublicKey).toBe(b64uEncode(wallet.sign.publicKey));
  });
});
