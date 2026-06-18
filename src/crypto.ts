import nacl from 'tweetnacl';

/** X25519 box keypair (the dApp's per-session `dappKey`). */
export interface BoxKeyPair {
  publicKey: Uint8Array; // 32 bytes
  secretKey: Uint8Array; // 32 bytes
}

/** Generate a fresh ephemeral X25519 keypair. */
export function newBoxKeyPair(): BoxKeyPair {
  return nacl.box.keyPair();
}

/** Reconstruct an X25519 keypair from a persisted 32-byte secret. */
export function boxKeyPairFromSecret(secretKey: Uint8Array): BoxKeyPair {
  return nacl.box.keyPair.fromSecretKey(secretKey);
}

/** 24-byte random nonce for a NaCl box. */
export function randomNonce(): Uint8Array {
  return nacl.randomBytes(nacl.box.nonceLength); // 24
}

/**
 * NaCl box (X25519 + XSalsa20-Poly1305): encrypt `message` to `theirPublicKey`
 * with `mySecretKey` under `nonce`. Matches the wallet's request/response AEAD.
 */
export function boxSeal(
  message: Uint8Array,
  nonce: Uint8Array,
  theirPublicKey: Uint8Array,
  mySecretKey: Uint8Array,
): Uint8Array {
  return nacl.box(message, nonce, theirPublicKey, mySecretKey);
}

/** NaCl box open. Returns null on MAC failure (do not distinguish reasons). */
export function boxOpen(
  ciphertext: Uint8Array,
  nonce: Uint8Array,
  theirPublicKey: Uint8Array,
  mySecretKey: Uint8Array,
): Uint8Array | null {
  return nacl.box.open(ciphertext, nonce, theirPublicKey, mySecretKey);
}

/**
 * Verify the wallet's detached Ed25519 response signature over `message` (the
 * UTF-8 bytes of the canonical subject) against the session `signingPublicKey`
 * advertised at connect.
 */
export function verifyEd25519(
  message: Uint8Array,
  signature: Uint8Array,
  publicKey: Uint8Array,
): boolean {
  return nacl.sign.detached.verify(message, signature, publicKey);
}
