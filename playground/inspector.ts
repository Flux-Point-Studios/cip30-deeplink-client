// DOM glue for the CIP-30-DeepLink inspector. All verification logic lives in
// inspect-core.ts (unit-tested against the shipped decoder); this file only
// reads inputs, calls the core, and renders the step report.
import { b64uDecode, b64uEncode } from '../src/base64url.js';
import { newBoxKeyPair, randomNonce } from '../src/crypto.js';
import { bytesToHex, hexToBytes } from '../src/protocol.js';
import {
  buildConnectRequest,
  inspectConnectResponse,
  simulateConnectResponse,
  type ConnectReport,
  type ResponseFlaw,
  type RefWalletKeys,
} from './inspect-core.js';

// Fixed demo material = the published known-answer-vector keys, so the presets
// are byte-for-byte reproducible against conformance/connect-kat.json.
const DEMO_DAPP_SECRET = new Uint8Array(32).fill(1);
const DEMO_NONCE = new Uint8Array(24).fill(4);
const DEMO_REF: RefWalletKeys = {
  boxSecret: new Uint8Array(32).fill(2),
  signSeed: new Uint8Array(32).fill(3),
  responseNonce: new Uint8Array(24).fill(5),
};
const DEMO_REDIRECT = 'https://aegis.example/cb';

// State: the dApp secret + request nonce that pair with the response under test.
let currentDappSecret: Uint8Array | null = DEMO_DAPP_SECRET;
let currentNonce: Uint8Array | null = DEMO_NONCE;

const $ = (id: string): HTMLElement => document.getElementById(id)!;
const val = (id: string): string => ($(id) as HTMLInputElement | HTMLTextAreaElement).value.trim();
const setVal = (id: string, v: string): void => {
  ($(id) as HTMLInputElement | HTMLTextAreaElement).value = v;
};

/** Parse a key/nonce field: 64-hex => bytes, else strict base64url. Empty => null. */
function parseBytes(s: string): Uint8Array | null {
  const t = s.trim();
  if (!t) return null;
  if (/^[0-9a-fA-F]+$/.test(t) && t.length % 2 === 0) return hexToBytes(t);
  return b64uDecode(t);
}

function statusGlyph(status: string): string {
  return status === 'pass' ? '✓' : status === 'fail' ? '✗' : status === 'skip' ? '○' : 'ℹ';
}

function render(report: ConnectReport): void {
  const banner = $('verdict');
  if (report.verdict === 'accept') {
    banner.className = 'verdict accept';
    banner.textContent = '✓ ACCEPT — a conforming dApp seats this session';
  } else if (report.verdict === 'wallet-rejected') {
    banner.className = 'verdict warn';
    banner.textContent = `⚠ WALLET REJECTED — errorCode ${report.errorCode ?? '?'}`;
  } else {
    banner.className = 'verdict reject';
    banner.textContent = `✗ REJECT — a conforming dApp throws${report.errorCode != null ? ` (errorCode ${report.errorCode})` : ''}`;
  }

  const steps = $('steps');
  steps.innerHTML = '';
  for (const s of report.steps) {
    const row = document.createElement('div');
    row.className = `step ${s.status}`;
    const code = s.code != null ? ` <span class="code">[${s.code}]</span>` : '';
    row.innerHTML = `<span class="glyph">${statusGlyph(s.status)}</span><span class="label">${s.label}${code}</span><span class="detail">${escapeHtml(s.detail)}</span>`;
    steps.appendChild(row);
  }

  const canon = $('canonical');
  if (report.canonicalSubject) {
    canon.textContent = report.canonicalSubject;
    $('canonical-wrap').style.display = 'block';
  } else {
    $('canonical-wrap').style.display = 'none';
  }

  const sess = $('session');
  if (report.session) {
    sess.textContent = JSON.stringify(report.session, null, 2);
    $('session-wrap').style.display = 'block';
  } else {
    $('session-wrap').style.display = 'none';
  }
  $('results').style.display = 'block';
}

function escapeHtml(s: string): string {
  return s.replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]!));
}

function runInspect(): void {
  const responseUrl = val('response-url');
  if (!responseUrl) return;
  let dappSecretKey: Uint8Array | undefined;
  let expectedNonce: Uint8Array | undefined;
  try {
    dappSecretKey = parseBytes(val('dapp-secret')) ?? undefined;
    expectedNonce = parseBytes(val('req-nonce')) ?? undefined;
  } catch (e) {
    alert(`Could not parse the dApp secret / nonce: ${(e as Error).message}`);
    return;
  }
  render(inspectConnectResponse({ responseUrl, dappSecretKey, expectedNonce }));
}

/** Load a preset: build the fixed-key request, simulate the chosen response. */
function loadPreset(flaw: ResponseFlaw): void {
  const req = buildConnectRequest({ dappSecretKey: DEMO_DAPP_SECRET, nonce: DEMO_NONCE, redirectUrl: DEMO_REDIRECT });
  const responseUrl = simulateConnectResponse(req.url, DEMO_REF, flaw);
  currentDappSecret = DEMO_DAPP_SECRET;
  currentNonce = DEMO_NONCE;
  setVal('response-url', responseUrl);
  setVal('dapp-secret', bytesToHex(DEMO_DAPP_SECRET));
  setVal('req-nonce', b64uEncode(DEMO_NONCE));
  runInspect();
}

/** Build a FRESH request to hand to a real wallet; stash its secret+nonce. */
function buildFreshRequest(): void {
  const kp = newBoxKeyPair();
  const nonce = randomNonce();
  currentDappSecret = kp.secretKey;
  currentNonce = nonce;
  const req = buildConnectRequest({ dappSecretKey: kp.secretKey, nonce, redirectUrl: val('fresh-redirect') || DEMO_REDIRECT });
  $('request-url').textContent = req.url; // #request-url is a <pre>, not an input
  setVal('dapp-secret', bytesToHex(kp.secretKey));
  setVal('req-nonce', b64uEncode(nonce));
  $('request-wrap').style.display = 'block';
}

function bootstrap(): void {
  $('btn-inspect').addEventListener('click', runInspect);
  $('btn-build').addEventListener('click', buildFreshRequest);
  document.querySelectorAll<HTMLButtonElement>('[data-preset]').forEach((b) =>
    b.addEventListener('click', () => loadPreset(b.dataset.preset as ResponseFlaw)),
  );
  loadPreset('none'); // open on a fully-green example
}

if (typeof document !== 'undefined') bootstrap();
