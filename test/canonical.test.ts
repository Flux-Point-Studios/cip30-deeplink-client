import { describe, expect, it } from 'vitest';
import { canonicalSubject, strictUnreservedEncode } from '../src/canonical.js';

describe('canonicalSubject (parity with Yuti AttestationBuilder)', () => {
  it('matches the byte-exact contract: domain sep, lowercased host, sorted query', () => {
    const url =
      'https://aegis.fluxpointstudios.com/cb' +
      '?response=approved&nonce=AAAA&payload=BBBB&signature=CCCC';
    // Domain separator + scheme://host/path + '?' + (signature-stripped,
    // key-sorted) query. This string MUST equal Yuti's Dart output for the
    // same input — it is the cross-implementation signing contract.
    expect(canonicalSubject(url)).toBe(
      'cip30dl-v1\n' +
        'https://aegis.fluxpointstudios.com/cb' +
        '?nonce=AAAA&payload=BBBB&response=approved',
    );
  });

  it('lowercases the host but not the path or values', () => {
    const url = 'https://Aegis.FluxPoint.COM/CB?response=approved&x=Yy';
    expect(canonicalSubject(url)).toBe(
      'cip30dl-v1\nhttps://aegis.fluxpoint.com/CB?response=approved&x=Yy',
    );
  });

  it('preserves an explicit non-default port', () => {
    const url = 'https://localhost:8080/cb?response=approved';
    expect(canonicalSubject(url)).toBe(
      'cip30dl-v1\nhttps://localhost:8080/cb?response=approved',
    );
  });

  it('strictly percent-encodes reserved characters over UTF-8, uppercase hex', () => {
    expect(strictUnreservedEncode('a b/c')).toBe('a%20b%2Fc');
    expect(strictUnreservedEncode('A.Z_9~-')).toBe('A.Z_9~-'); // unreserved kept
    expect(strictUnreservedEncode('é')).toBe('%C3%A9'); // 2-byte UTF-8
  });
});
