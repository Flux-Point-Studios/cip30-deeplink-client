// A minimal wallet mirroring the Yuti reference (ephemeral X25519 box + Ed25519
// session key over the canonical subject), used to exercise the SDK end-to-end.
import nacl from 'tweetnacl';
import { b64uDecode, b64uEncode, utf8Decode, utf8Encode } from '../src/base64url.js';
import { canonicalSubject } from '../src/canonical.js';
import { bytesToHex } from '../src/protocol.js';

export function parseParams(url: string): Record<string, string> {
  const q = url.slice(url.indexOf('?') + 1);
  const out: Record<string, string> = {};
  for (const pair of q.split('&')) {
    const i = pair.indexOf('=');
    out[pair.slice(0, i)] = pair.slice(i + 1);
  }
  return out;
}

export const TEST_ADDRESS =
  'addr_test1qqqt0pru382hy9vjlsxv3ye02z50sfvt8xunscg5pgden77z73dpdfng2ctw2ekqplqgrljelz7h4dneac27nn3qx3rqqpavzj';

export class FakeYutiWallet {
  readonly box = nacl.box.keyPair();
  readonly sign = nacl.sign.keyPair();
  sessionId = 'sess-' + bytesToHex(nacl.randomBytes(4));
  readonly witness = nacl.randomBytes(40);

  constructor(private readonly redirect: string) {}

  handleConnect(url: string): string {
    const p = parseParams(url);
    const dappPub = b64uDecode(p.dappKey!);
    const chain = decodeURIComponent(p.chain!);
    const sessionJson = JSON.stringify({
      session: this.sessionId,
      network: chain === 'cardano:mainnet' ? 1 : 0,
      addresses: [TEST_ADDRESS],
      chain,
      walletId: 'yuti',
      expiresAt: 1900000000,
      signingPublicKey: b64uEncode(this.sign.publicKey),
    });
    const wnonce = nacl.randomBytes(24);
    const cipher = nacl.box(utf8Encode(sessionJson), wnonce, dappPub, this.box.secretKey);
    return (
      `${this.redirect}?response=approved` +
      `&walletKey=${b64uEncode(this.box.publicKey)}` +
      `&nonce=${b64uEncode(wnonce)}` +
      `&payload=${b64uEncode(cipher)}`
    );
  }

  handleSignTx(url: string): { responseUrl: string; requestTx: string } {
    const p = parseParams(url);
    const dappPub = b64uDecode(p.dappKey!);
    const reqPlain = nacl.box.open(
      b64uDecode(p.payload!),
      b64uDecode(p.nonce!),
      dappPub,
      this.box.secretKey,
    );
    if (!reqPlain) throw new Error('wallet could not decrypt the signTx request');
    const requestTx = (JSON.parse(utf8Decode(reqPlain)) as { tx: string }).tx;
    const wnonce = nacl.randomBytes(24);
    const cipher = nacl.box(this.witness, wnonce, dappPub, this.box.secretKey);
    const base =
      `${this.redirect}?response=approved` +
      `&nonce=${b64uEncode(wnonce)}` +
      `&payload=${b64uEncode(cipher)}`;
    const sig = nacl.sign.detached(utf8Encode(canonicalSubject(base)), this.sign.secretKey);
    return { responseUrl: `${base}&signature=${b64uEncode(sig)}`, requestTx };
  }

  reject(redirect: string, code: number, message: string): string {
    return (
      `${redirect}?response=rejected` +
      `&errorCode=${code}` +
      `&errorMessage=${encodeURIComponent(message)}`
    );
  }
}

/** A localStorage-shaped in-memory store for tests. */
export class MemoryStore {
  private m = new Map<string, string>();
  getItem(k: string): string | null {
    return this.m.has(k) ? this.m.get(k)! : null;
  }
  setItem(k: string, v: string): void {
    this.m.set(k, v);
  }
  removeItem(k: string): void {
    this.m.delete(k);
  }
}
