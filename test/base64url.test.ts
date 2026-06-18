import { describe, expect, it } from 'vitest';
import { b64uDecode, b64uEncode, b64uEncodeText } from '../src/base64url.js';

describe('strict unpadded base64url', () => {
  it('encodes without padding, url alphabet', () => {
    // 0xff 0xff 0xff -> "____" ... pick bytes that exercise - and _
    expect(b64uEncode(new Uint8Array([0xfb, 0xff, 0xbf]))).toBe('-_-_');
    expect(b64uEncode(new Uint8Array([0]))).toBe('AA');
    expect(b64uEncode(new Uint8Array([0, 0]))).toBe('AAA');
    expect(b64uEncode(new Uint8Array([]))).toBe('');
  });

  it('round-trips arbitrary byte lengths (no padding needed on decode)', () => {
    for (let n = 0; n < 40; n++) {
      const bytes = new Uint8Array(n);
      for (let i = 0; i < n; i++) bytes[i] = (i * 37 + 11) & 0xff;
      expect(Array.from(b64uDecode(b64uEncode(bytes)))).toEqual(
        Array.from(bytes),
      );
    }
  });

  it('decodes a value the wallet would emit (padded input also tolerated)', () => {
    const text = '{"name":"Aegis"}';
    const enc = b64uEncodeText(text);
    expect(enc).not.toContain('=');
    expect(new TextDecoder().decode(b64uDecode(enc))).toBe(text);
    // padded variant still decodes
    expect(new TextDecoder().decode(b64uDecode(enc + '='))).toBe(text);
  });

  it('rejects invalid characters', () => {
    expect(() => b64uDecode('not valid!')).toThrow();
  });
});
