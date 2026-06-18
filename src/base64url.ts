// Strict, unpadded base64url — byte-identical to the wallet side (Yuti uses
// Dart's base64Url with '=' stripped; decode tolerates the missing padding).
// Pure (no Buffer / atob) so the SDK runs unchanged in browsers and Node.

const ALPHABET =
  'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
const LOOKUP: Record<string, number> = {};
for (let i = 0; i < ALPHABET.length; i++) LOOKUP[ALPHABET[i]!] = i;

/** Encode bytes to unpadded base64url. */
export function b64uEncode(bytes: Uint8Array): string {
  let out = '';
  for (let i = 0; i < bytes.length; i += 3) {
    const b0 = bytes[i]!;
    const b1 = i + 1 < bytes.length ? bytes[i + 1]! : 0;
    const b2 = i + 2 < bytes.length ? bytes[i + 2]! : 0;
    out += ALPHABET[b0 >> 2];
    out += ALPHABET[((b0 & 0x03) << 4) | (b1 >> 4)];
    if (i + 1 < bytes.length) out += ALPHABET[((b1 & 0x0f) << 2) | (b2 >> 6)];
    if (i + 2 < bytes.length) out += ALPHABET[b2 & 0x3f];
  }
  return out;
}

/** Decode unpadded (or padded) base64url to bytes. Throws on invalid input. */
export function b64uDecode(input: string): Uint8Array {
  const s = input.replace(/=+$/, '');
  const out = new Uint8Array(Math.floor((s.length * 6) / 8));
  let bits = 0;
  let value = 0;
  let p = 0;
  for (let i = 0; i < s.length; i++) {
    const c = LOOKUP[s[i]!];
    if (c === undefined) {
      throw new Error(`invalid base64url character "${s[i]}"`);
    }
    value = (value << 6) | c;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out[p++] = (value >> bits) & 0xff;
    }
  }
  return out.subarray(0, p);
}

const TEXT_ENCODER = new TextEncoder();
const TEXT_DECODER = new TextDecoder();

export const utf8Encode = (s: string): Uint8Array => TEXT_ENCODER.encode(s);
export const utf8Decode = (b: Uint8Array): string => TEXT_DECODER.decode(b);

/** base64url of a UTF-8 string (used for the `dapp` info parameter). */
export const b64uEncodeText = (s: string): string => b64uEncode(utf8Encode(s));
