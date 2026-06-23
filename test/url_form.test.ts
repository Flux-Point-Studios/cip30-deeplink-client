/**
 * D:\aegis\frontend\src\wallet\cip186\__tests__\url_form.test.ts
 *
 * Locks the request-URL FORM selection: a wallet that advertises an https
 * universal-link prefix (Gero) must get the https form
 * (`<prefix>connect` / `<prefix>signTx`), while a wallet without one (Yuti)
 * keeps the custom scheme (`cip30dl-<id>:/v1/connect`). iOS Safari silently
 * drops custom-scheme navigations but opens universal links, so using the
 * prefix is what makes Gero connect actually launch the app.
 *
 * The https connect form is checked against CIP-0186 vector
 * decode_001_connect_https_minimal (`https://<host>/cip30dl/v1/connect?...`):
 * same query params, only the base differs from the scheme form.
 */
import nacl from 'tweetnacl';
import { describe, expect, it } from 'vitest';
import {
  buildConnectUrl,
  buildSignTxUrl,
  endpointBase,
  walletScheme,
} from '../src/protocol.js';

const GERO_PREFIX = 'https://cip30dl.gerowallet.io/cip30dl/v1/';
const REDIRECT = 'https://aegis.example/cb';

const connectArgs = (httpsPrefix?: string) => ({
  scheme: walletScheme('gero'),
  httpsPrefix,
  chain: 'cardano:mainnet',
  redirectUrl: REDIRECT,
  dappInfo: { name: 'Aegis', url: 'https://aegis.example' },
  dappPublicKey: new Uint8Array(32).fill(1),
  nonce: new Uint8Array(24).fill(2),
});

describe('endpointBase: https prefix wins over custom scheme', () => {
  it('uses the https prefix when present', () => {
    expect(endpointBase('cip30dl-gero', GERO_PREFIX)).toBe(GERO_PREFIX);
  });
  it('falls back to the custom scheme when no/empty prefix', () => {
    expect(endpointBase('cip30dl-yuti')).toBe('cip30dl-yuti:/v1/');
    expect(endpointBase('cip30dl-yuti', '')).toBe('cip30dl-yuti:/v1/');
  });
});

describe('buildConnectUrl form selection', () => {
  it('Gero (httpsPrefix) → https universal-link form with the spec params', () => {
    const url = buildConnectUrl(connectArgs(GERO_PREFIX));
    expect(url.startsWith(`${GERO_PREFIX}connect?v=1`)).toBe(true);
    // Matches the decode_001_connect_https_minimal param set.
    const q = new URL(url).searchParams;
    expect(q.get('v')).toBe('1');
    expect(q.get('dapp')).toBeTruthy();
    expect(q.get('dappKey')).toBeTruthy();
    expect(q.get('redirect')).toBe(REDIRECT);
    expect(q.get('chain')).toBe('cardano:mainnet');
    expect(q.get('nonce')).toBeTruthy();
  });

  it('Yuti (no prefix) → custom scheme form, params unchanged', () => {
    const url = buildConnectUrl({ ...connectArgs(undefined), scheme: walletScheme('yuti') });
    expect(url.startsWith('cip30dl-yuti:/v1/connect?v=1')).toBe(true);
    expect(url).toContain('&chain=cardano%3Amainnet');
    expect(url).toContain(`&redirect=${encodeURIComponent(REDIRECT)}`);
  });
});

describe('buildSignTxUrl form selection', () => {
  const wallet = nacl.box.keyPair.fromSecretKey(new Uint8Array(32).fill(5));
  const dapp = nacl.box.keyPair.fromSecretKey(new Uint8Array(32).fill(7));
  const signArgs = (httpsPrefix?: string) => ({
    scheme: walletScheme('gero'),
    httpsPrefix,
    redirectUrl: REDIRECT,
    dappPublicKey: dapp.publicKey,
    dappSecretKey: dapp.secretKey,
    walletPublicKey: wallet.publicKey,
    commit: new Uint8Array(32).fill(9),
    payload: { session: 's', tx: 'deadbeef', partialSign: true, vkeyHints: [] },
    nonce: new Uint8Array(24).fill(3),
    ttl: 1_810_000_300,
  });

  it('Gero (httpsPrefix) → https signTx form', () => {
    const url = buildSignTxUrl(signArgs(GERO_PREFIX));
    expect(url.startsWith(`${GERO_PREFIX}signTx?v=1`)).toBe(true);
    const q = new URL(url).searchParams;
    expect(q.get('dappKey')).toBeTruthy();
    expect(q.get('commit')).toBeTruthy();
    expect(q.get('ttl')).toBe('1810000300');
    expect(q.get('payload')).toBeTruthy();
  });

  it('Yuti (no prefix) → custom scheme signTx form', () => {
    const url = buildSignTxUrl({ ...signArgs(undefined), scheme: walletScheme('yuti') });
    expect(url.startsWith('cip30dl-yuti:/v1/signTx?v=1')).toBe(true);
  });
});
