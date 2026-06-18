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

function asUrl(responseUrl: string | URL): URL {
  return typeof responseUrl === 'string' ? new URL(responseUrl) : responseUrl;
}

/** The signature-stripped, key-sorted, strict-encoded query string. */
function encodedQuery(url: URL): string {
  const pairs: Array<[string, string]> = [];
  url.searchParams.forEach((v, k) => {
    if (k !== 'signature') pairs.push([k, v]);
  });
  // Stable sort by key (insertion order preserved for equal keys), matching the
  // wallet's `compareTo`-with-stable-fallback.
  pairs.sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0));
  return pairs
    .map(([k, v]) => `${strictUnreservedEncode(k)}=${strictUnreservedEncode(v)}`)
    .join('&');
}

function subjectWith(url: URL, path: string, query: string): string {
  const host = url.hostname.toLowerCase();
  const port = url.port ? ':' + url.port : '';
  return `${SUBJECT_DOMAIN_SEPARATOR}${url.protocol.replace(':', '')}://${host}${port}${path}?${query}`;
}

/**
 * Returns the canonical byte-string (as a JS string; sign over its UTF-8 bytes)
 * the wallet Ed25519-signs for a response. The `signature` parameter is
 * excluded; remaining params are stable-sorted by key. Mirrors the six-step
 * procedure in spec §Response signing §Signature construction.
 *
 * Note: for an authority-only URL with no path, this uses WHATWG `URL.pathname`
 * (`'/'`). The *path* of a path-less redirect is canonicalized inconsistently
 * across URL libraries (`''` in RFC-3986 / Dart `Uri.path`, `'/'` in WHATWG),
 * and the received URL may already have been normalized by the browser/OS — so
 * for VERIFICATION use [canonicalSubjectCandidates], which accepts both forms.
 */
export function canonicalSubject(responseUrl: string | URL): string {
  const url = asUrl(responseUrl);
  return subjectWith(url, url.pathname, encodedQuery(url));
}

/**
 * All canonical subjects a conformant wallet could have signed for this
 * response, to verify against robustly. Identical to [canonicalSubject] except
 * that for a root/empty path it also yields the `''` and `'/'` path variants —
 * closing the cross-implementation empty-path ambiguity (Dart `Uri.path` `''`
 * vs WHATWG `URL.pathname` `'/'`) and any browser/OS normalization of the
 * received URL. Both variants describe the same dApp-controlled redirect, so
 * accepting either is safe (the host is independently validated; the params and
 * signature are unchanged).
 */
export function canonicalSubjectCandidates(responseUrl: string | URL): string[] {
  const url = asUrl(responseUrl);
  const query = encodedQuery(url);
  const out = new Set<string>([subjectWith(url, url.pathname, query)]);
  if (url.pathname === '/' || url.pathname === '') {
    out.add(subjectWith(url, '', query));
    out.add(subjectWith(url, '/', query));
  }
  return [...out];
}
