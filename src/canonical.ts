import { utf8Encode } from './base64url.js';

// Canonical-form domain separator (spec §Response signing). The wallet signs
// `${SUBJECT_DOMAIN_SEPARATOR}${scheme}://${host}[:port]${path}?${sortedQuery}`
// with its session Ed25519 key; the dApp re-derives the identical bytes to
// verify. Byte-for-byte parity with Yuti AttestationBuilder.canonicalSubject.
export const SUBJECT_DOMAIN_SEPARATOR = 'cip30dl-v1\n';

const UNRESERVED = /[A-Za-z0-9._~-]/;

/** Strict percent-encoding over UTF-8 bytes: unreserved kept, else %XX upper. */
export function strictUnreservedEncode(input: string): string {
  let out = '';
  for (const b of utf8Encode(input)) {
    const ch = String.fromCharCode(b);
    out += UNRESERVED.test(ch)
      ? ch
      : '%' + b.toString(16).toUpperCase().padStart(2, '0');
  }
  return out;
}

/**
 * Returns the canonical byte-string (as a JS string; sign over its UTF-8 bytes)
 * the wallet Ed25519-signs for a response. The `signature` parameter is
 * excluded; remaining params are stable-sorted by key. Mirrors the six-step
 * procedure in spec §Response signing §Signature construction.
 */
export function canonicalSubject(responseUrl: string | URL): string {
  const url = typeof responseUrl === 'string' ? new URL(responseUrl) : responseUrl;
  const host = url.hostname.toLowerCase();
  const port = url.port ? ':' + url.port : '';
  const schemeAndAuthority =
    url.protocol.replace(':', '') + '://' + host + port + url.pathname;

  const pairs: Array<[string, string]> = [];
  url.searchParams.forEach((v, k) => {
    if (k !== 'signature') pairs.push([k, v]);
  });
  // Stable sort by key (insertion order preserved for equal keys), matching the
  // wallet's `compareTo`-with-stable-fallback.
  pairs.sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0));

  const encoded = pairs
    .map(([k, v]) => `${strictUnreservedEncode(k)}=${strictUnreservedEncode(v)}`)
    .join('&');

  return `${SUBJECT_DOMAIN_SEPARATOR}${schemeAndAuthority}?${encoded}`;
}
