import { describe, expect, it } from 'vitest';
import { bytesToHex, DeepLinkClient, DeepLinkRejection } from '../src/index.js';
import { FakeYutiWallet, MemoryStore } from './fake-wallet.js';

const REDIRECT = 'https://aegis.fluxpointstudios.com/cb';
const FIXED_HASH = 'a'.repeat(64); // 32-byte tx hash (hex)

function makeClient(storage: MemoryStore, captured: string[]): DeepLinkClient {
  return new DeepLinkClient({
    wallet: 'yuti',
    chain: 'cardano:preprod',
    redirectUrl: REDIRECT,
    storage,
    navigate: (u) => captured.push(u),
    resolveTxHash: () => FIXED_HASH,
  });
}

describe('DeepLinkClient stateful flow', () => {
  it('connect -> resume -> signTx -> resume yields a verified witness', async () => {
    const storage = new MemoryStore();
    const captured: string[] = [];
    const client = makeClient(storage, captured);
    const wallet = new FakeYutiWallet(REDIRECT);

    await client.connect({ name: 'Aegis', url: 'https://aegis.fluxpointstudios.com' });
    expect(captured[0]).toContain('cip30dl-yuti:/v1/connect');

    const r1 = await client.resume(wallet.handleConnect(captured[0]!));
    expect(r1?.kind).toBe('connect');
    expect(client.getSession()?.session).toBe(wallet.sessionId);

    await client.signTx({ tx: '84a40080018002000300a0f5f6' });
    expect(captured[1]).toContain('cip30dl-yuti:/v1/signTx');

    const { responseUrl } = wallet.handleSignTx(captured[1]!);
    const r2 = await client.resume(responseUrl);
    expect(r2?.kind).toBe('signTx');
    if (r2?.kind === 'signTx') {
      expect(r2.result.signatureValid).toBe(true);
      expect(r2.result.txHash).toBe(FIXED_HASH);
      expect(r2.result.witnessSet).toBe(bytesToHex(wallet.witness));
    }
  });

  it('signTx before connect throws', async () => {
    const client = makeClient(new MemoryStore(), []);
    await expect(client.signTx({ tx: '84a4' })).rejects.toThrow(/not connected/);
  });

  it('resume surfaces a wallet rejection as DeepLinkRejection', async () => {
    const storage = new MemoryStore();
    const captured: string[] = [];
    const client = makeClient(storage, captured);
    const wallet = new FakeYutiWallet(REDIRECT);

    await client.connect({ name: 'Aegis', url: 'https://aegis.fluxpointstudios.com' });
    const rejected = wallet.reject(REDIRECT, -1, 'user rejected the connection');
    await expect(client.resume(rejected)).rejects.toBeInstanceOf(DeepLinkRejection);
  });

  it('resume returns null when there is no pending request', async () => {
    const client = makeClient(new MemoryStore(), []);
    expect(await client.resume(`${REDIRECT}?response=approved&x=1`)).toBeNull();
  });

  it('disconnect clears the session', async () => {
    const storage = new MemoryStore();
    const captured: string[] = [];
    const client = makeClient(storage, captured);
    const wallet = new FakeYutiWallet(REDIRECT);
    await client.connect({ name: 'Aegis', url: 'https://aegis.fluxpointstudios.com' });
    await client.resume(wallet.handleConnect(captured[0]!));
    expect(client.getSession()).not.toBeNull();
    client.disconnect();
    expect(client.getSession()).toBeNull();
  });
});
