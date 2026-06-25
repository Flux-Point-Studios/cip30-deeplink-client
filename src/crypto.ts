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

/**
 * Byte-equality for the connect nonce echo. The echoed nonce is a PUBLIC value
 * (it travels in cleartext on the wire), so a constant-time compare protects
 * nothing here — a length check + per-byte XOR is sufficient and honest.
 */
export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i]! ^ b[i]!;
  return diff === 0;
}
