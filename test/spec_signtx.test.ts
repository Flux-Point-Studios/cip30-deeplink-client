/**
 * D:\aegis\frontend\src\wallet\cip186\__tests__\spec_signtx.test.ts
 *
 * Locks the CIP-0186 `spec` signTx wire format (Gero) against the published
 * test vectors in cardano-foundation/CIPs#1189, alongside the unchanged
 * `sdk-legacy` format (Yuti). The two diverge ONLY on signTx (connect is
 * byte-identical):
 *   - request `tx`: spec = base64url(CBOR); legacy = hex.
 *   - response payload: spec = `{ commit, witnessSet, txHash }` JSON envelope
 *     (all base64url) the dApp MUST commit-echo verify (mismatch ⇒ -2); legacy
 *     = the raw `transaction_witness_set` CBOR.
 *
 * Vector values are inlined verbatim (with their source filename) so the suite
 * is hermetic — the vectors live in the separate CIP repo and aren't on the
 * frontend's CI path. Crypto is exercised end-to-end (NaCl-box seal/open +
 * Ed25519 response signing) so the assertions cover the real decode path, not
 * a stub.
 */
import nacl from 'tweetnacl';
import { describe, expect, it } from 'vitest';
import { b64uDecode, b64uEncode, utf8Encode } from '../src/base64url.js';
import { canonicalSubject } from '../src/canonical.js';
import { DeepLinkClient } from '../src/client.js';
import {
  bytesToHex,
  decodeSignTxResponse,
  hexToBytes,
} from '../src/protocol.js';
import { DeepLinkRejection, type Session } from '../src/types.js';

// --- vector fixtures (verbatim) -------------------------------------------

// cbor_001_commit_blake2b256_of_txbody.json
const CBOR_001 = {
  commit_hex: 'd36a2619a672494604e11bb447cbcf5231e9f2ba25c2169177edc941bd50ad6c',
  commit_base64url: '02omGaZySUYE4Ru0R8vPUjHp8rolwhaRd-3JQb1QrWw',
};

// response_005_signTx_result_shape.json (commit echoes the request)
const RESP_005 = {
  envelope: {
    commit: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
    witnessSet:
      'oQCBglggAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABYQBEREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREQ',
    txHash: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
  },
  request_commit_b64url: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
};

// response_006_signTx_commit_echo_mismatch.json (request commit ≠ envelope)
const RESP_006_MISMATCH_COMMIT = '__________________________________________8';

// --- helpers: act as a conformant wallet to build a signed response --------

interface WalletKit {
  boxPublic: Uint8Array;
  boxSecret: Uint8Array;
  signPublic: Uint8Array;
  signSecret: Uint8Array;
}

function newWalletKit(seed: number): WalletKit {
  const box = nacl.box.keyPair.fromSecretKey(new Uint8Array(32).fill(seed));
  const sign = nacl.sign.keyPair.fromSeed(new Uint8Array(32).fill(seed ^ 0x5a));
  return {
    boxPublic: box.publicKey,
    boxSecret: box.secretKey,
    signPublic: sign.publicKey,
    signSecret: sign.secretKey,
  };
}

function sessionFor(wallet: WalletKit): Session {
  return {
    session: 'sess-1',
    network: 0,
    addresses: ['addr_test1qq'],
    chain: 'cardano:preprod',
    walletId: 'gero',
    expiresAt: 0,
    signingPublicKey: b64uEncode(wallet.signPublic),
    walletKey: b64uEncode(wallet.boxPublic),
  };
}

/** Seal `plaintextBytes` to the dApp and return a signed wallet response URL. */
function sealedResponseUrl(args: {
  redirectUrl: string;
  plaintext: Uint8Array;
  wallet: WalletKit;
  dappBoxPublic: Uint8Array;
}): string {
  const nonce = new Uint8Array(24).fill(7);
  const cipher = nacl.box(args.plaintext, nonce, args.dappBoxPublic, args.wallet.boxSecret);
  const base =
    `${args.redirectUrl}?response=approved` +
    `&payload=${b64uEncode(cipher)}` +
    `&nonce=${b64uEncode(nonce)}`;
  // The wallet signs the canonical subject (which strips `signature`), so it is
  // identical whether computed before or after appending the signature param.
  const subject = canonicalSubject(base);
  const sig = nacl.sign.detached(utf8Encode(subject), args.wallet.signSecret);
  return `${base}&signature=${b64uEncode(sig)}`;
}

// --- request side: tx encoding differs by signFormat -----------------------

/** A minimal in-memory KeyValueStore. */
function memStore(): Record<string, string> & {
  getItem(k: string): string | null;
  setItem(k: string, v: string): void;
  removeItem(k: string): void;
} {
  const map = new Map<string, string>();
  return {
    getItem: (k) => map.get(k) ?? null,
    setItem: (k, v) => void map.set(k, v),
    removeItem: (k) => void map.delete(k),
  } as ReturnType<typeof memStore>;
}

const TX_HEX = '84a0a0f5f6'; // cbor_002_tx_body_extraction_index_0.json transaction_cbor_hex

function captureSignTxRequest(signFormat: 'sdk-legacy' | 'spec'): {
  txParam: string;
} {
  const wallet = newWalletKit(3);
  const storage = memStore();
  // Seed a dapp box keypair and a live session so signTx() can run.
  const dapp = nacl.box.keyPair.fromSecretKey(new Uint8Array(32).fill(9));
  storage.setItem('cip30dl:dappkey:gero', b64uEncode(dapp.secretKey));
  storage.setItem('cip30dl:session:gero', JSON.stringify(sessionFor(wallet)));

  let navigated = '';
  const client = new DeepLinkClient({
    wallet: 'gero',
    chain: 'cardano:preprod',
    redirectUrl: 'https://aegis.example/cb',
    storage,
    signFormat,
    navigate: (url) => {
      navigated = url;
    },
    now: () => 1_810_000_000,
  });

  // commit must be 32 bytes; pass the cbor_001 commit explicitly.
  void client.signTx({ tx: TX_HEX, commit: CBOR_001.commit_base64url });

  const url = new URL(navigated);
  const payloadB64 = url.searchParams.get('payload')!;
  const nonceB64 = url.searchParams.get('nonce')!;
  const dappKeyB64 = url.searchParams.get('dappKey')!;
  const plain = nacl.box.open(
    b64uDecode(payloadB64),
    b64uDecode(nonceB64),
    b64uDecode(dappKeyB64),
    wallet.boxSecret,
  )!;
  const payload = JSON.parse(new TextDecoder().decode(plain)) as { tx: string };
  return { txParam: payload.tx };
}

// --- tests -----------------------------------------------------------------

describe('CIP-0186 commit (base64url of the 32-byte tx hash)', () => {
  it('base64url-encodes the BLAKE2b-256 commit per cbor_001', () => {
    expect(b64uEncode(hexToBytes(CBOR_001.commit_hex))).toBe(
      CBOR_001.commit_base64url,
    );
  });
});

describe('signTx request `tx` encoding by signFormat', () => {
  it('spec encodes tx as base64url(CBOR)', () => {
    const { txParam } = captureSignTxRequest('spec');
    expect(txParam).toBe(b64uEncode(hexToBytes(TX_HEX)));
  });

  it('sdk-legacy keeps tx as hex', () => {
    const { txParam } = captureSignTxRequest('sdk-legacy');
    expect(txParam).toBe(TX_HEX);
  });
});

describe('spec signTx response: { commit, witnessSet, txHash } envelope', () => {
  const redirect = 'https://aegis.example/cb';

  it('accepts + extracts the witness set when the commit echoes (response_005)', () => {
    const wallet = newWalletKit(11);
    const dapp = nacl.box.keyPair.fromSecretKey(new Uint8Array(32).fill(13));
    const url = sealedResponseUrl({
      redirectUrl: redirect,
      plaintext: utf8Encode(JSON.stringify(RESP_005.envelope)),
      wallet,
      dappBoxPublic: dapp.publicKey,
    });

    const out = decodeSignTxResponse({
      responseUrl: url,
      dappSecretKey: dapp.secretKey,
      session: sessionFor(wallet),
      format: 'spec',
      expectedCommit: b64uDecode(RESP_005.request_commit_b64url),
    });

    expect(out.signatureValid).toBe(true);
    expect(out.txHash).toBe(RESP_005.envelope.txHash);
    expect(out.witnessSet).toBe(bytesToHex(b64uDecode(RESP_005.envelope.witnessSet)));
  });

  it('rejects with -2 CommitMismatch when the commit does not echo (response_006)', () => {
    const wallet = newWalletKit(17);
    const dapp = nacl.box.keyPair.fromSecretKey(new Uint8Array(32).fill(19));
    const url = sealedResponseUrl({
      redirectUrl: redirect,
      plaintext: utf8Encode(JSON.stringify(RESP_005.envelope)),
      wallet,
      dappBoxPublic: dapp.publicKey,
    });

    try {
      decodeSignTxResponse({
        responseUrl: url,
        dappSecretKey: dapp.secretKey,
        session: sessionFor(wallet),
        format: 'spec',
        expectedCommit: b64uDecode(RESP_006_MISMATCH_COMMIT),
      });
      throw new Error('expected a commit-mismatch rejection');
    } catch (e) {
      expect(e).toBeInstanceOf(DeepLinkRejection);
      expect((e as DeepLinkRejection).errorCode).toBe(-2);
    }
  });
});

describe('sdk-legacy signTx response (Yuti) is unchanged', () => {
  it('decrypts the raw witness CBOR with no envelope/commit-echo', () => {
    const wallet = newWalletKit(23);
    const dapp = nacl.box.keyPair.fromSecretKey(new Uint8Array(32).fill(29));
    const rawWitness = hexToBytes('a10081825820' + '11'.repeat(32) + '5840' + '22'.repeat(64));
    const url = sealedResponseUrl({
      redirectUrl: 'https://aegis.example/cb',
      plaintext: rawWitness,
      wallet,
      dappBoxPublic: dapp.publicKey,
    });

    const out = decodeSignTxResponse({
      responseUrl: url,
      dappSecretKey: dapp.secretKey,
      session: sessionFor(wallet),
      // format omitted ⇒ defaults to sdk-legacy
    });

    expect(out.signatureValid).toBe(true);
    expect(out.txHash).toBeUndefined();
    expect(out.witnessSet).toBe(bytesToHex(rawWitness));
  });
});
