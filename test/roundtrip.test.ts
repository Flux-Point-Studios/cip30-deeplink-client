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
import { FakeYutiWallet, TEST_ADDRESS as ADDRESS } from './fake-wallet.js';

const SCHEME = 'cip30dl-yuti';
const REDIRECT = 'https://aegis.fluxpointstudios.com/cb';

describe('connect + signTx round-trip against a Yuti-compatible wallet', () => {
  it('connect: dApp decrypts the session JSON and adopts walletKey', () => {
    const dapp = nacl.box.keyPair();
    const wallet = new FakeYutiWallet(REDIRECT);

    const connectUrl = buildConnectUrl({
      scheme: SCHEME,
      chain: 'cardano:preprod',
      redirectUrl: REDIRECT,
      dappInfo: { name: 'Aegis', url: 'https://aegis.fluxpointstudios.com' },
      dappPublicKey: dapp.publicKey,
      nonce: nacl.randomBytes(24),
    });
    const responseUrl = wallet.handleConnect(connectUrl);
    const session = decodeConnectResponse({ responseUrl, dappSecretKey: dapp.secretKey });

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

    // establish the session
    const session = decodeConnectResponse({
      responseUrl: wallet.handleConnect(
        buildConnectUrl({
          scheme: SCHEME,
          chain: 'cardano:preprod',
          redirectUrl: REDIRECT,
          dappInfo: { name: 'Aegis', url: 'https://aegis.fluxpointstudios.com' },
          dappPublicKey: dapp.publicKey,
          nonce: nacl.randomBytes(24),
        }),
      ),
      dappSecretKey: dapp.secretKey,
    });

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

  it('signTx: a tampered response signature fails verification', () => {
    const dapp = nacl.box.keyPair();
    const wallet = new FakeYutiWallet(REDIRECT);
    const session = decodeConnectResponse({
      responseUrl: wallet.handleConnect(
        buildConnectUrl({
          scheme: SCHEME,
          chain: 'cardano:preprod',
          redirectUrl: REDIRECT,
          dappInfo: { name: 'Aegis', url: 'https://aegis.fluxpointstudios.com' },
          dappPublicKey: dapp.publicKey,
          nonce: nacl.randomBytes(24),
        }),
      ),
      dappSecretKey: dapp.secretKey,
    });
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
