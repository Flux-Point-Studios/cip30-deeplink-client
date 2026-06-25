// DOM glue for the CIP-30-DeepLink inspector. All verification logic lives in
// inspect-core.ts (unit-tested against the shipped decoder); this file only
// reads inputs, calls the core, and renders the step report with clear feedback.
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

const PRESET_LABEL: Record<ResponseFlaw, string> = {
  none: 'Valid signed connect',
  echoMismatch: 'Echo mismatch (replay)',
  tamperSignature: 'Tampered signature',
  unsigned: 'Legacy / unsigned wallet',
};

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

function escapeHtml(s: string): string {
  return s.replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]!));
}

function setBanner(cls: string, text: string): void {
  const b = $('verdict');
  b.className = `verdict ${cls}`;
  b.textContent = text;
  // Re-trigger the flash animation on every (re-)render so a click is always felt.
  b.classList.remove('flash');
  void b.offsetWidth;
  b.classList.add('flash');
}

/** Empty/landing state: inputs are filled, but no result yet — the first Inspect
 *  click produces a visible result, so the tool reads as interactive. */
function showEmptyState(): void {
  $('results').style.display = 'block';
  const b = $('verdict');
  b.className = 'verdict empty';
  b.textContent = '↑ Click an example, or hit “Inspect” to verify the response above';
  b.classList.remove('flash');
  $('steps').innerHTML = '';
  $('steps').style.opacity = '1';
  $('canonical-wrap').style.display = 'none';
  $('session-wrap').style.display = 'none';
}

function showError(msg: string): void {
  $('results').style.display = 'block';
  setBanner('reject', `✗ ${msg}`);
  $('steps').innerHTML = '';
  $('steps').style.opacity = '1';
  $('canonical-wrap').style.display = 'none';
  $('session-wrap').style.display = 'none';
}

function render(report: ConnectReport): void {
  $('steps').style.opacity = '1';
  if (report.verdict === 'accept') {
    setBanner('accept', '✓ ACCEPT — a conforming dApp seats this session');
  } else if (report.verdict === 'wallet-rejected') {
    setBanner('warn', `⚠ WALLET REJECTED — errorCode ${report.errorCode ?? '?'}`);
  } else {
    setBanner('reject', `✗ REJECT — a conforming dApp throws${report.errorCode != null ? ` (errorCode ${report.errorCode})` : ''}`);
  }

  const steps = $('steps');
  steps.innerHTML = '';
  report.steps.forEach((s, i) => {
    const row = document.createElement('div');
    row.className = `step ${s.status} reveal`;
    row.style.animationDelay = `${i * 55}ms`;
    const code = s.code != null ? ` <span class="code">[${s.code}]</span>` : '';
    row.innerHTML = `<span class="glyph">${statusGlyph(s.status)}</span><span class="label">${s.label}${code}</span><span class="detail">${escapeHtml(s.detail)}</span>`;
    steps.appendChild(row);
  });

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
}

function scrollVerdictIntoView(): void {
  const r = $('verdict').getBoundingClientRect();
  if (r.top < 0 || r.bottom > window.innerHeight) {
    $('verdict').scrollIntoView({ behavior: 'smooth', block: 'center' });
  }
}

/** Run inspection with a visible "Verifying…" beat so every click is felt. */
function runInspect(opts: { scroll?: boolean } = {}): void {
  const responseUrl = val('response-url');
  if (!responseUrl) {
    showError('Paste a connect response URL above (or click an example).');
    return;
  }
  let dappSecretKey: Uint8Array | undefined;
  let expectedNonce: Uint8Array | undefined;
  try {
    dappSecretKey = parseBytes(val('dapp-secret')) ?? undefined;
    expectedNonce = parseBytes(val('req-nonce')) ?? undefined;
  } catch (e) {
    showError(`Couldn’t parse the dApp secret / nonce: ${(e as Error).message}`);
    return;
  }

  $('results').style.display = 'block';
  setBanner('verifying', '⏳ Verifying…');
  $('steps').style.opacity = '0.3';
  $('canonical-wrap').style.display = 'none';
  $('session-wrap').style.display = 'none';

  window.setTimeout(() => {
    render(inspectConnectResponse({ responseUrl, dappSecretKey, expectedNonce }));
    if (opts.scroll) scrollVerdictIntoView();
  }, 320);
}

/** Load a preset: fill the fixed-key request + simulated response, then verify. */
function loadPreset(flaw: ResponseFlaw): void {
  const req = buildConnectRequest({ dappSecretKey: DEMO_DAPP_SECRET, nonce: DEMO_NONCE, redirectUrl: DEMO_REDIRECT });
  setVal('response-url', simulateConnectResponse(req.url, DEMO_REF, flaw));
  setVal('dapp-secret', bytesToHex(DEMO_DAPP_SECRET));
  setVal('req-nonce', b64uEncode(DEMO_NONCE));
  document.querySelectorAll<HTMLButtonElement>('[data-preset]').forEach((b) =>
    b.classList.toggle('active', b.dataset.preset === flaw),
  );
  runInspect({ scroll: true });
}

/** Build a FRESH request to hand to a real wallet; stash its secret+nonce. */
function buildFreshRequest(): void {
  const kp = newBoxKeyPair();
  const nonce = randomNonce();
  const req = buildConnectRequest({ dappSecretKey: kp.secretKey, nonce, redirectUrl: val('fresh-redirect') || DEMO_REDIRECT });
  $('request-url').textContent = req.url; // #request-url is a <pre>
  setVal('dapp-secret', bytesToHex(kp.secretKey));
  setVal('req-nonce', b64uEncode(nonce));
  $('request-wrap').style.display = 'block';
  $('request-hint').style.display = 'block';
}

function bootstrap(): void {
  $('btn-inspect').addEventListener('click', () => runInspect({ scroll: true }));
  $('btn-build').addEventListener('click', buildFreshRequest);
  document.querySelectorAll<HTMLButtonElement>('[data-preset]').forEach((b) =>
    b.addEventListener('click', () => loadPreset(b.dataset.preset as ResponseFlaw)),
  );
  // Re-inspect on Enter from any input.
  ['dapp-secret', 'req-nonce'].forEach((id) =>
    $(id).addEventListener('keydown', (e) => {
      if ((e as KeyboardEvent).key === 'Enter') runInspect({ scroll: true });
    }),
  );

  // Land pre-filled with the valid example, but show the empty-state so the
  // user's first Inspect (or example click) produces a visible result.
  const req = buildConnectRequest({ dappSecretKey: DEMO_DAPP_SECRET, nonce: DEMO_NONCE, redirectUrl: DEMO_REDIRECT });
  setVal('response-url', simulateConnectResponse(req.url, DEMO_REF, 'none'));
  setVal('dapp-secret', bytesToHex(DEMO_DAPP_SECRET));
  setVal('req-nonce', b64uEncode(DEMO_NONCE));
  showEmptyState();
}

if (typeof document !== 'undefined') bootstrap();
