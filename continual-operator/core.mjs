// Continual's health report and fixed menu: the module an app runs. MIT licence (c) 2026 GlueView Inc.
//
// WHAT IT IS. A small piece of your app that rides its own traffic. When someone uses the app, and this running copy of
// it has not checked in for a while (five minutes by default, `checkin_minutes` in continual.operator.json, never less
// than one), it makes ONE outbound call to Continual after the response has gone out: "anything for me?" Continual
// answers with any instructions it signed for this app. Each is checked (below); the ones on the app's menu run, and
// each result goes back in one outbound call, tied to the instruction's nonce.
//
// The app opens nothing: there is no route, no port and no inbound request. The health report is read-only: the version
// running, the jobs and queues continual.operator.json lists, whether the database and services it lists answer. It
// returns no rows, no records, no settings, no error messages and no secrets, and it runs nothing it was sent: an
// instruction names an operation from a fixed list in this file, never code. A check-in never delays, changes or fails
// the app's own response: it runs after the response (the platform's waitUntil, or not awaited at all), each call has
// a short timeout, and every failure is caught and said in one quiet line at most.
//
// THE FIXED MENU (F-84 (1); B9 part 2). Beside the health report, a short list of operations an app may declare under
// `menu` in continual.operator.json, each run only through what the app declares:
//   maintenance_on · _extend · _off   the app serves a maintenance page (`hold` below), for four hours at most
//   readonly_on · _extend · _off      the app refuses writes in its declared way, for four hours at most
//   feature_off · feature_on          a named feature the declaration lists, through the app's own hook
//   job_rerun                         a named job the declaration lists, through the app's own hook
//   cache_clear                       a named cache the declaration lists, through the app's own hook
// This module holds the maintenance page's and read-only mode's expiry itself: each turns off at its time whether or not
// Continual is ever heard from again. A menu operation runs only with the app's own key (CONTINUAL_OPERATOR_KEY in the
// app's environment, made by its owner; Continual holds only its public half): every check-in and result is then signed
// with it, and an instruction for the menu names that key. Each result is `done` or one word, never data. There is no
// eval and no shell: a hook is a function the app's own code registers by name.
//
// "At most once per window" holds per running copy of the app. A host that runs several copies (serverless instances,
// Workers isolates) may check in from a few of them in the same window. Each copy holds its own maintenance page and
// read-only mode; it tells Continual which it holds at each check-in, and Continual hands it what it is missing.
//
// HOW AN INSTRUCTION IS CHECKED, in this order, before anything runs (a refusal names the check in one word):
//   1. switched_off     CONTINUAL_OPERATOR=off in the app's environment, or "enabled": false in the declaration —
//                       then the app does not check in at all, and serves no maintenance page.
//   2. unsigned         no instruction.
//      malformed        not a compact JWS: base64url header.payload.signature, ES256 (ECDSA P-256, SHA-256).
//      unknown_key      the header's `kid` is not one of the public keys beside this file (keys.mjs).
//      bad_signature    the signature does not verify against that public key. Continual signs with the private
//                       half, held in AWS KMS; this module holds nothing of Continual's that is secret.
//   3. wrong_app        the payload's `app` is not the declaration's app_id.
//   4. too_long         `exp` is not after `iat`, or more than five minutes after it; or a maintenance page or read-only
//                       mode asked to last more than four hours from the moment it was signed.
//      expired          now is past `exp` (five minutes' leeway for clocks), or past the page's or mode's own end.
//      not_yet          `iat` is in the future (the same leeway).
//   5. wrong_operation  `op` is not an operation this module implements.
//      not_on_menu      `op` is one it implements, but the declaration leaves it out (`operations`, or `menu`).
//   6. no_app_key       a menu operation, and this copy has no CONTINUAL_OPERATOR_KEY it can read.
//      wrong_key        a menu operation for another app key than the one in this copy's environment.
//      bad_args         a menu operation whose arguments are not the ones it takes.
//      not_declared     a feature, job or cache the declaration's `menu` does not list by that name.
//      no_hook          declared, but the app's code registers no hook for it.
//      not_on           an extension for a page or mode this copy is not showing.
//   7. replayed         the `nonce` was seen before. Each running copy of the app remembers the nonces it saw until
//                       they expire; pass `seen` (a shared store) to make that hold across copies.
// Only then does the operation run. A hook that throws or runs past five seconds is reported as `hook_failed` or
// `timeout`, never its error's text. A refusal after a good signature is reported back with the nonce, so the owner
// sees why (a clock that is off, a menu that leaves the operation out).
//
// A CLOCK THAT IS OFF (1.1.1). Continual takes a check-in signed with the app's key only when the time it carries is
// within five minutes of Continual's, and this module takes an instruction within the same five minutes either way.
// Further off, Continual answers with how far (`clock_off_s`, a number), and the module says so in one log line of its
// own words — never text from the answer.
//
// Every runtime this targets has Web Crypto, atob, btoa, TextEncoder and fetch (Node 18+, Deno, Cloudflare, Netlify,
// Vercel), so this file imports nothing.

export const MODULE_VERSION = '1.2.0'; // 1.2.0 (7 Oct 2026): adapters/node.mjs, for a plain Node server
export const INSTRUCTION_TYPE = 'continual-instruction';
export const MAX_LIFE_S = 300; // an instruction lives five minutes at most
export const LEEWAY_S = 300; // clocks may disagree by up to five minutes: the window Continual takes a signed check-in in
export const CONTINUAL_URL = 'https://api.glueview.com/v1/operator'; // the check-in and the report; pinned, never read from the environment
export const CALL_TIMEOUT_MS = 3000; // each outbound call; a slow Continual is a skipped check-in, never a slow app
export const CHECKIN_MINUTES = 5; // the default window; continual.operator.json may set 1 to 60
export const MODE_MAX_S = 4 * 3600; // a maintenance page or read-only mode lasts four hours at most from the click that set it
export const HOOK_MS = 5000; // each menu hook the app registers
export const APP_KEY_ENV = 'CONTINUAL_OPERATOR_KEY'; // the app's own private key, base64url PKCS#8 — never sent, never logged
const SIGNATURE_HEADER = 'x-continual-app-signature'; // <app key id>.<ES256 signature, base64url>, over "<kind>.<body>"
const MAX_INSTRUCTION = 4096;
const MAX_INSTRUCTIONS = 5; // per check-in
const MAX_ANSWER = 65536;
const MAX_ENTRIES = 20; // per list in the declaration
const APP_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const NONCE = /^[A-Za-z0-9_-]{16,64}$/;
const B64URL = /^[A-Za-z0-9_-]+$/;
const NAME = /^[A-Za-z0-9][A-Za-z0-9 ._:/()-]{0,59}$/;
const ENV_NAME = /^[A-Z][A-Z0-9_]{0,63}$/;
const VERSION = /^[A-Za-z0-9._+-]{1,64}$/;
// The variables hosts set to the commit or build being served. Fixed, so the declaration cannot point the report at
// any other variable.
export const VERSION_ENVS = ['CONTINUAL_VERSION', 'VERCEL_GIT_COMMIT_SHA', 'COMMIT_REF', 'CF_PAGES_COMMIT_SHA', 'RENDER_GIT_COMMIT',
  'RAILWAY_GIT_COMMIT_SHA', 'SOURCE_VERSION', 'HEROKU_SLUG_COMMIT', 'GIT_COMMIT', 'GITHUB_SHA'];
// The default port for a database address that names none.
const PORTS = { postgres: 5432, postgresql: 5432, mysql: 3306, mariadb: 3306, redis: 6379, rediss: 6379, mongodb: 27017, sqlserver: 1433 };
const WRITES = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);
const enc = new TextEncoder();
const dec = new TextDecoder();

/**
 * The fixed menu: each operation, what in the declaration's `menu` must list it, and its arguments. Nothing else is on
 * it, and nothing the declaration leaves out runs.
 */
export const MENU = {
  maintenance_on: { mode: 'maintenance', args: 'until' },
  maintenance_extend: { mode: 'maintenance', args: 'until' },
  maintenance_off: { mode: 'maintenance', args: null },
  readonly_on: { mode: 'readonly', args: 'until' },
  readonly_extend: { mode: 'readonly', args: 'until' },
  readonly_off: { mode: 'readonly', args: null },
  feature_off: { list: 'features', args: 'name', hook: 'off' },
  feature_on: { list: 'features', args: 'name', hook: 'on' },
  job_rerun: { list: 'jobs', args: 'name' },
  cache_clear: { list: 'caches', args: 'name' },
};

/** base64url (or base64) to bytes. */
export function fromB64url(s) {
  const b64 = String(s).replace(/-/g, '+').replace(/_/g, '/');
  const bin = atob(b64 + '='.repeat((4 - (b64.length % 4)) % 4));
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

/** bytes to base64url. */
export function toB64url(bytes) {
  let bin = '';
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/** base64url to bytes, or null when it does not decode (a length no encoder writes). */
function bytesOf(s) {
  try { return fromB64url(s); } catch { return null; } // not base64: the caller refuses it as malformed
}

/** A JSON object from bytes, or null for anything else. */
function objectOf(bytes) {
  if (!bytes) return null;
  try {
    const v = JSON.parse(dec.decode(bytes));
    return v && typeof v === 'object' && !Array.isArray(v) ? v : null;
  } catch { return null; } // not JSON: the caller refuses it as malformed
}

const refuse = (reason, nonce = null) => ({ ok: false, reason, ...(nonce ? { nonce } : {}) });
const keyCache = new Map();
function verifyingKey(subtle, spki) {
  if (!keyCache.has(spki)) keyCache.set(spki, subtle.importKey('spki', fromB64url(spki), { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']));
  return keyCache.get(spki);
}

/**
 * The nonces this running copy has seen, kept until each instruction expires. `claim` answers 'ok' the first time,
 * 'seen' after, and 'full' (fail closed) if ten thousand live nonces are held at once, which Continual's pace never
 * reaches: it signs at most one instruction a minute per app.
 */
export function memoryNonces({ max = 10000 } = {}) {
  const held = new Map(); // nonce → kept until (epoch seconds); inserted in time order
  return {
    async claim(nonce, until, nowS = Math.floor(Date.now() / 1000)) {
      for (const [k, u] of held) { if (u >= nowS) break; held.delete(k); }
      if (held.has(nonce)) return 'seen';
      if (held.size >= max) return 'full';
      held.set(nonce, until);
      return 'ok';
    },
  };
}

/**
 * Check one instruction. `keys`: [{ kid, spki }] (spki base64 or base64url DER); `ops`: the operations this module
 * implements; `menu`: the ones the app's declaration allows; `seen`: a nonce store with `claim(nonce, until)`;
 * `appKid`: the id of the app's own key in this copy's environment, or null; `limits(op, args, payload, nowS)`: the
 * declaration's own limits for a menu operation, a refusal word or null.
 * Returns { ok: true, instruction } or { ok: false, reason }, the reason one of the words in the header above; a refusal
 * after the signature verified carries the instruction's `nonce`, so it can be reported.
 */
export async function verifyInstruction(token, { appId, keys = [], ops = [], menu = [], seen, now = Date.now(), subtle = globalThis.crypto?.subtle, appKid = null, limits = null } = {}) {
  if (typeof token !== 'string' || !token) return refuse('unsigned');
  if (token.length > MAX_INSTRUCTION) return refuse('malformed');
  const parts = token.split('.');
  if (parts.length !== 3 || !parts.every((p) => B64URL.test(p))) return refuse('malformed');
  const header = objectOf(bytesOf(parts[0]));
  if (!header || header.alg !== 'ES256' || header.typ !== INSTRUCTION_TYPE || typeof header.kid !== 'string') return refuse('malformed');
  const key = keys.find((k) => k && k.kid === header.kid && typeof k.spki === 'string');
  if (!key) return refuse('unknown_key');
  const signature = bytesOf(parts[2]);
  if (!signature || signature.length !== 64) return refuse('bad_signature');
  let good = false;
  try {
    good = await subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, await verifyingKey(subtle, key.spki), signature, enc.encode(`${parts[0]}.${parts[1]}`));
  } catch { good = false; } // a key that will not import verifies nothing
  if (!good) return refuse('bad_signature');
  const p = objectOf(bytesOf(parts[1]));
  if (!p || p.v !== 1 || p.iss !== 'continual' || typeof p.app !== 'string' || typeof p.op !== 'string' || !NONCE.test(String(p.nonce ?? ''))
    || !Number.isInteger(p.iat) || !Number.isInteger(p.exp)) return refuse('malformed');
  if (p.app !== appId) return refuse('wrong_app', p.nonce);
  if (p.exp <= p.iat || p.exp - p.iat > MAX_LIFE_S) return refuse('too_long', p.nonce);
  const nowS = Math.floor(now / 1000);
  if (nowS > p.exp + LEEWAY_S) return refuse('expired', p.nonce);
  if (p.iat > nowS + LEEWAY_S) return refuse('not_yet', p.nonce);
  if (!ops.includes(p.op)) return refuse('wrong_operation', p.nonce);
  if (!menu.includes(p.op)) return refuse('not_on_menu', p.nonce);
  const args = p.args && typeof p.args === 'object' && !Array.isArray(p.args) ? p.args : null;
  if (MENU[p.op]) {
    // A menu operation is for one app key: the one whose private half is in this copy's environment.
    if (!appKid) return refuse('no_app_key', p.nonce);
    if (p.akid !== appKid) return refuse('wrong_key', p.nonce);
  }
  const limit = typeof limits === 'function' ? limits(p.op, args, p, nowS) : null;
  if (limit) return refuse(limit, p.nonce);
  const claim = seen ? await seen.claim(p.nonce, p.exp + LEEWAY_S, nowS) : 'none';
  if (claim !== 'ok' && claim !== true) return refuse(claim === 'full' ? 'busy' : 'replayed', p.nonce);
  return { ok: true, instruction: { app: p.app, op: p.op, nonce: p.nonce, iat: p.iat, exp: p.exp, kid: header.kid, args, akid: typeof p.akid === 'string' ? p.akid : null } };
}

// ── the declaration ────────────────────────────────────────────────────────────

const envNames = (v) => [].concat(v ?? []).filter((x) => typeof x === 'string' && ENV_NAME.test(x)).slice(0, 4);
const timeoutOf = (v) => (Number.isInteger(v) ? Math.min(5000, Math.max(100, v)) : 2000);
const httpsUrl = (v) => {
  if (typeof v !== 'string') return null;
  try { const u = new URL(v); return u.protocol === 'https:' && !u.username && !u.password ? u.toString() : null; } catch { return null; } // not a URL: dropped and counted
};

/**
 * continual.operator.json, read the one way this module reads it. Entries it cannot read are dropped and counted in
 * `ignored`, which the report carries so the owner sees it. Nothing undeclared is ever reported.
 */
export function readDeclaration(declared) {
  const d = declared && typeof declared === 'object' && !Array.isArray(declared) ? declared : {};
  let ignored = 0;
  const list = (v, clean) => {
    const raw = Array.isArray(v) ? v : [];
    const out = [];
    for (const x of raw.slice(0, MAX_ENTRIES)) {
      const name = x && typeof x === 'object' && typeof x.name === 'string' && NAME.test(x.name) ? x.name : null;
      const entry = name && !out.some((o) => o.name === name) ? clean(x, name) : null;
      if (entry) out.push(entry); else ignored += 1;
    }
    ignored += Math.max(0, raw.length - MAX_ENTRIES);
    return out;
  };
  const appId = typeof d.app_id === 'string' && APP_ID.test(d.app_id.toLowerCase()) ? d.app_id.toLowerCase() : null;
  const operations = Array.isArray(d.operations) ? d.operations.filter((o) => typeof o === 'string') : ['health'];
  const jobs = list(d.jobs, (x, name) => ({ name, timeout_ms: timeoutOf(x.timeout_ms) }));
  const queues = list(d.queues, (x, name) => ({ name, timeout_ms: timeoutOf(x.timeout_ms) }));
  const dependencies = list(d.dependencies, (x, name) => {
    const path = typeof x.path === 'string' && /^\/[^\s]{0,199}$/.test(x.path) ? x.path : null;
    const how = { name, timeout_ms: timeoutOf(x.timeout_ms) };
    if (x.tcp_env != null) { const env = envNames(x.tcp_env); return env.length ? { ...how, tcp_env: env } : null; }
    if (x.url != null) { const url = httpsUrl(x.url); return url ? { ...how, url, path } : null; }
    if (x.url_env != null) { const env = envNames(x.url_env); return env.length ? { ...how, url_env: env, path } : null; }
    return how; // answered by a check the route file registers, or reported as not checked
  });
  const checkinMinutes = Number.isInteger(d.checkin_minutes) ? Math.min(60, Math.max(1, d.checkin_minutes)) : CHECKIN_MINUTES;
  const menu = menuOf(d.menu, () => { ignored += 1; });
  return { appId, enabled: d.enabled !== false, operations, jobs, queues, dependencies, ignored, checkinMinutes, menu };
}

const MESSAGE = /^[^<>]{1,200}$/;
/**
 * The declaration's `menu`: what the app lets Continual operate, by name. Absent, nothing on the menu runs.
 *   "maintenance": true, or { "message": "…" }        the page this module serves while it is up
 *   "readonly": true, or { "refuse": "writes" | "hook" }  "writes": this module answers POST, PUT, PATCH and DELETE
 *                                                       with 503 while it is on; "hook": the app's own readonly hooks do
 *   "features" · "jobs" · "caches": ["name", …]         each run through a hook the app's code registers by that name
 */
export function menuOf(m, drop = () => {}) {
  const d = m && typeof m === 'object' && !Array.isArray(m) ? m : {};
  const names = (v) => {
    const out = [];
    for (const x of (Array.isArray(v) ? v : []).slice(0, MAX_ENTRIES)) {
      const name = typeof x === 'string' ? x : x && typeof x === 'object' ? x.name : null;
      if (typeof name === 'string' && NAME.test(name) && !out.includes(name)) out.push(name); else drop();
    }
    return out;
  };
  const mt = d.maintenance === true ? {} : d.maintenance && typeof d.maintenance === 'object' ? d.maintenance : null;
  const ro = d.readonly === true ? {} : d.readonly && typeof d.readonly === 'object' ? d.readonly : null;
  const refuse = ro && (ro.refuse ?? 'writes');
  if (ro && !['writes', 'hook'].includes(refuse)) drop();
  return {
    maintenance: mt ? { message: typeof mt.message === 'string' && MESSAGE.test(mt.message.trim()) ? mt.message.trim() : null } : null,
    readonly: ro && ['writes', 'hook'].includes(refuse) ? { refuse } : null,
    features: names(d.features), jobs: names(d.jobs), caches: names(d.caches),
  };
}

/** The operations a declaration allows: `operations` (the health report), and what its `menu` lists. */
export function allowedOps(config) {
  const m = config.menu ?? menuOf(null);
  const listed = (op) => {
    const spec = MENU[op];
    return spec.mode ? !!m[spec.mode] : m[spec.list].length > 0;
  };
  return [...config.operations.filter((op) => !MENU[op]), ...Object.keys(MENU).filter(listed)];
}

// ── the health report ─────────────────────────────────────────────────────────

function withTimeout(promise, ms) {
  let timer;
  const late = new Promise((_, reject) => { timer = setTimeout(() => reject(new Error('timeout')), ms); });
  return Promise.race([Promise.resolve(promise), late]).finally(() => clearTimeout(timer));
}
const isoOrNull = (v) => {
  const t = v instanceof Date ? v.getTime() : typeof v === 'string' || typeof v === 'number' ? new Date(v).getTime() : NaN;
  return Number.isFinite(t) ? new Date(t).toISOString() : null;
};
const firstEnv = (env, names) => names.map((n) => env(n)).find((v) => typeof v === 'string' && v.trim()) ?? null;

/** The commit or build id the host says it is serving, from the fixed list above; null when none is set. */
export function versionOf(env) {
  const v = firstEnv(env, VERSION_ENVS);
  return v && VERSION.test(v.trim()) ? v.trim() : null;
}

async function jobState(job, check) {
  if (typeof check !== 'function') return { name: job.name, reported: false, last_run: null, ok: null };
  try {
    const r = await withTimeout(check(), job.timeout_ms);
    return { name: job.name, reported: true, last_run: isoOrNull(r?.last_run), ok: typeof r?.ok === 'boolean' ? r.ok : null };
  } catch { return { name: job.name, reported: false, last_run: null, ok: null, why: 'check_failed' }; } // the error's text could hold data: only the word goes out
}

async function queueDepth(queue, check) {
  if (typeof check !== 'function') return { name: queue.name, reported: false, depth: null };
  try {
    const n = Number(await withTimeout(check(), queue.timeout_ms));
    return Number.isFinite(n) && n >= 0 ? { name: queue.name, reported: true, depth: Math.min(Math.floor(n), 1e9) } : { name: queue.name, reported: false, depth: null, why: 'not_a_count' };
  } catch { return { name: queue.name, reported: false, depth: null, why: 'check_failed' }; } // only the word goes out
}

/** Whether one declared dependency answers: a registered check, a TCP connect, or an HTTPS request whose status is read and whose body is never read. */
async function answers(dep, { env, check, tcp, fetch: send, now }) {
  const t0 = now();
  const done = (ok, why = null) => ({ name: dep.name, answers: ok, ms: ok == null ? null : Math.max(0, Math.round(now() - t0)), ...(why ? { why } : {}) });
  const failed = (e) => done(false, e?.message === 'timeout' ? 'timeout' : 'no_answer');
  if (typeof check === 'function') {
    try { await withTimeout(check(), dep.timeout_ms); return done(true); } catch (e) { return failed(e); }
  }
  if (dep.tcp_env) {
    const raw = firstEnv(env, dep.tcp_env);
    let host = null; let port = null;
    try { const u = new URL(raw ?? ''); host = u.hostname || null; port = Number(u.port) || PORTS[u.protocol.replace(/:$/, '')] || null; } catch { host = null; } // unset or not an address: said below
    if (!host || !port) return done(null, 'no_address');
    if (typeof tcp !== 'function') return done(null, 'not_checkable_here');
    try { await withTimeout(tcp(host, port, dep.timeout_ms), dep.timeout_ms); return done(true); } catch (e) { return failed(e); }
  }
  if (dep.url || dep.url_env) {
    const base = dep.url ?? httpsUrl(firstEnv(env, dep.url_env));
    if (!base) return done(null, 'no_address');
    const target = dep.path ? new URL(dep.path, base).toString() : base;
    const ctl = new AbortController();
    try {
      const res = await withTimeout(send(target, { method: 'GET', redirect: 'manual', signal: ctl.signal, headers: { 'user-agent': `continual-operator/${MODULE_VERSION}` } }), dep.timeout_ms);
      await res.body?.cancel?.(); // the status is the answer; the body is never read
      return res.status >= 500 ? done(false, 'server_error') : done(true);
    } catch (e) { ctl.abort(); return failed(e); }
  }
  return done(null, 'not_checked');
}

/** The read-only health report: only what the declaration lists, each value in a fixed shape. */
export async function healthReport({ config, env = () => undefined, checks = {}, tcp = null, fetch: send = globalThis.fetch, now = () => Date.now() }) {
  const [jobs, queues, dependencies] = await Promise.all([
    Promise.all(config.jobs.map((j) => jobState(j, checks.jobs?.[j.name]))),
    Promise.all(config.queues.map((q) => queueDepth(q, checks.queues?.[q.name]))),
    Promise.all(config.dependencies.map((d) => answers(d, { env, check: checks.dependencies?.[d.name], tcp, fetch: send, now }))),
  ]);
  return { at: new Date(now()).toISOString(), version: versionOf(env), jobs, queues, dependencies, ...(config.ignored ? { ignored: config.ignored } : {}) };
}

/** The operations this module implements. Each runs only after an instruction naming it passed every check above. */
export const OPERATIONS = {
  health: { readOnly: true, run: (ctx) => healthReport(ctx) },
};

// ── the app's own key ─────────────────────────────────────────────────────────

/**
 * The app's key from CONTINUAL_OPERATOR_KEY: base64url (or base64) PKCS#8 DER of a P-256 private key, which the owner
 * made and set in the app's environment. Returns { kid, spki, sign(text) → base64url r||s }; the private half is
 * imported unextractable and never leaves this copy. `kid` is the first sixteen base64url characters of the SHA-256 of
 * the public half, as Continual names it. Throws when the value is not such a key.
 */
export async function importAppKey(raw, subtle = globalThis.crypto?.subtle) {
  const der = fromB64url(String(raw).replace(/\s+/g, ''));
  const alg = { name: 'ECDSA', namedCurve: 'P-256' };
  const whole = await subtle.importKey('pkcs8', der, alg, true, ['sign']);
  const jwk = await subtle.exportKey('jwk', whole);
  const pub = await subtle.importKey('jwk', { kty: 'EC', crv: 'P-256', x: jwk.x, y: jwk.y, ext: true }, alg, true, ['verify']);
  const spki = new Uint8Array(await subtle.exportKey('spki', pub));
  const signing = await subtle.importKey('pkcs8', der, alg, false, ['sign']);
  const kid = toB64url(new Uint8Array(await subtle.digest('SHA-256', spki))).slice(0, 16);
  return {
    kid, spki: toB64url(spki),
    sign: async (text) => toB64url(new Uint8Array(await subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, signing, enc.encode(text)))),
  };
}

// ── the check-in ──────────────────────────────────────────────────────────────

/**
 * One outbound JSON call with a short timeout: { status, body }. A failure throws to the caller's catch. With `signer`
 * (the app's key and what the call is), the body is signed: "<kind>.<body>", so a check-in's signature is never a report's.
 */
async function call(send, url, payload, signer = null) {
  const ctl = new AbortController();
  const timer = setTimeout(() => ctl.abort(), CALL_TIMEOUT_MS);
  try {
    const body = JSON.stringify(payload);
    const headers = { 'content-type': 'application/json', 'user-agent': `continual-operator/${MODULE_VERSION}` };
    if (signer) headers[SIGNATURE_HEADER] = `${signer.key.kid}.${await signer.key.sign(`${signer.kind}.${body}`)}`;
    const res = await send(url, { method: 'POST', redirect: 'manual', signal: ctl.signal, headers, body });
    const text = await res.text();
    let answer = null;
    try { answer = text.length <= MAX_ANSWER ? JSON.parse(text) : null; } catch { answer = null; } // not JSON: no instructions, said by the status
    return { status: res.status, body: answer };
  } finally { clearTimeout(timer); }
}

/** How far this server's clock is from Continual's, in the module's own words: "7 minutes behind", "2 hours ahead of". */
export function clockOffWords(skewS) {
  const a = Math.abs(Math.round(Number(skewS) || 0));
  const m = Math.max(1, Math.round(a / 60));
  const amount = m < 120 ? `${m} minute${m === 1 ? '' : 's'}` : m < 2880 ? `${Math.round(m / 60)} hours` : `${Math.round(m / 1440)} days`;
  return `${amount} ${skewS < 0 ? 'behind' : 'ahead of'}`;
}

/** The word for a failed check-in, never its text: a URL or an address in an error message stays in the app. */
const quietWord = (e) => (e?.name === 'AbortError' ? 'timeout' : typeof e?.word === 'string' ? e.word : 'unreachable');
const escapeHtml = (t) => String(t).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
const randomId = () => toB64url(globalThis.crypto.getRandomValues(new Uint8Array(16)));

/** What `hold` answers with, as a fetch Response, for the runtimes that speak Response; undefined to carry on. */
export function toResponse(held) {
  return held ? new Response(held.body, { status: held.status, headers: held.headers }) : undefined;
}

/**
 * The module for one app. `declared`: continual.operator.json; `keys`: keys.mjs's KEYS; `env(name)`: the app's
 * environment; `checks`: { jobs: { name: fn }, queues: { name: fn }, dependencies: { name: fn } } for what only the
 * app's own code can answer; `hooks`: { maintenance: { on, off }, readonly: { on, off }, features: { name: { off, on } },
 * jobs: { name: fn }, caches: { name: fn } } for the menu, each run only for what the declaration's `menu` lists;
 * `tcp(host, port, ms)`: a connect check where the runtime has sockets; `seen`: a shared nonce store, else this copy's
 * memory; `log(line)`: where the one quiet line goes (console.warn by default).
 * `tick()` is what a framework's wrapper calls on each request: it resolves, never rejects, and does nothing unless this
 * copy's window has passed. `hold({ method, accept })` is what it asks before the request goes on: null to carry on, or
 * the maintenance page or read-only answer to serve instead.
 */
export function createOperator({ declared, keys = [], env = () => undefined, checks = {}, hooks = {}, tcp = null, fetch: send = globalThis.fetch, seen = memoryNonces(), subtle = globalThis.crypto?.subtle, now = () => Date.now(), endpoint = CONTINUAL_URL, log = (line) => console.warn(line) } = {}) {
  const config = readDeclaration(declared);
  const allowed = allowedOps(config);
  const switchedOff = () => !config.enabled || /^(off|false|0|no)$/i.test(String(env('CONTINUAL_OPERATOR') ?? '').trim());
  let last = -Infinity; // when this copy last checked in
  let appKey; // undefined: not read yet; null: none in this copy's environment
  const modes = { maintenance: null, readonly: null }; // { until } — this copy's own, held here so each ends on time

  async function appKeyOf() {
    if (appKey !== undefined) return appKey;
    const raw = String(env(APP_KEY_ENV) ?? '').trim();
    if (!raw || !subtle) return (appKey = null);
    try { appKey = await importAppKey(raw, subtle); } catch {
      appKey = null; // not a key this module can read: the menu stays off in this copy; the value is never logged
      log(`continual-operator: ${APP_KEY_ENV} could not be read, so nothing on the menu runs here`);
    }
    return appKey;
  }

  const nowS = () => Math.floor(now() / 1000);
  const untilOf = (mode, t = nowS()) => (modes[mode] && modes[mode].until > t ? modes[mode].until : null);
  const hookOf = (op, name) => {
    const spec = MENU[op];
    if (spec.list === 'features') return hooks.features?.[name]?.[spec.hook];
    return hooks[spec.list]?.[name];
  };

  /** A hook, run with a time limit; its result is never read. 'done', or the word for how it failed. */
  async function runHook(fn, arg) {
    if (typeof fn !== 'function') return 'done';
    try { await withTimeout(fn(arg), HOOK_MS); return 'done'; } catch (e) { return e?.message === 'timeout' ? 'timeout' : 'hook_failed'; } // the error's text could hold data: only the word goes out
  }

  /** The declaration's own limits for a menu operation, checked after the signature and before anything runs. */
  function limits(op, args, p, t) {
    const spec = MENU[op];
    if (!spec) return null;
    const named = Object.keys(args ?? {});
    if (spec.args === null) return named.length ? 'bad_args' : null;
    if (named.length !== 1 || named[0] !== spec.args) return 'bad_args';
    if (spec.args === 'until') {
      if (!Number.isInteger(args.until)) return 'bad_args';
      if (args.until - p.iat > MODE_MAX_S) return 'too_long';
      if (args.until <= t) return 'expired';
      if (spec.mode === 'readonly' && config.menu.readonly?.refuse === 'hook' && (typeof hooks.readonly?.on !== 'function' || typeof hooks.readonly?.off !== 'function')) return 'no_hook';
      if (op.endsWith('_extend') && !untilOf(spec.mode, t)) return 'not_on';
      return null;
    }
    if (typeof args.name !== 'string' || !NAME.test(args.name)) return 'bad_args';
    if (!config.menu[spec.list].includes(args.name)) return 'not_declared';
    return typeof hookOf(op, args.name) === 'function' ? null : 'no_hook';
  }

  /** Run one menu operation that passed every check. 'done', or the one word for what failed. */
  async function runMenu(op, args) {
    const spec = MENU[op];
    if (!spec.mode) return runHook(hookOf(op, args.name));
    const mode = spec.mode;
    const was = untilOf(mode);
    if (op.endsWith('_off')) {
      modes[mode] = null; // this module's own part ends now, whatever the hook says
      return was ? runHook(hooks[mode]?.off) : 'done';
    }
    modes[mode] = { until: args.until };
    if (was) return 'done'; // an extension, or a copy already showing it: only the end moves
    const word = await runHook(hooks[mode]?.on, { until: new Date(args.until * 1000).toISOString() });
    if (word !== 'done') modes[mode] = null; // the app could not turn it on: nothing is shown as on
    return word;
  }

  /** A page or mode whose end has passed is off: the app's off hook is called once, here, in this copy. */
  function lapse(t = nowS()) {
    const ending = [];
    for (const mode of Object.keys(modes)) {
      if (modes[mode] && modes[mode].until <= t) { modes[mode] = null; ending.push(runHook(hooks[mode]?.off)); }
    }
    return Promise.all(ending);
  }

  /** What this copy holds, for the check-in: each mode's end (epoch seconds), or null. */
  const modesNow = () => ({ maintenance: untilOf('maintenance'), readonly: untilOf('readonly') });
  /** What the declaration lists on the menu, by name: never anything else. */
  const declaredMenu = () => ({ maintenance: !!config.menu.maintenance, readonly: config.menu.readonly?.refuse ?? null, features: config.menu.features, jobs: config.menu.jobs, caches: config.menu.caches });

  /** One check-in: ask, check each instruction, run the allowed ones, report each. Returns what it did. */
  async function checkIn() {
    await lapse();
    const key = await appKeyOf();
    const asking = { app: config.appId, module: MODULE_VERSION, kid: keys[0]?.kid ?? null, kids: keys.map((k) => k.kid).slice(0, 4) };
    // With the app's key, the check-in is signed, says when and once (at, cnonce), and says what this copy holds.
    if (key) Object.assign(asking, { akid: key.kid, at: now(), cnonce: randomId(), modes: modesNow(), menu: declaredMenu() });
    const signed = (kind) => (key ? { key, kind } : null);
    const asked = await call(send, `${endpoint}/checkin`, asking, signed('continual-checkin'));
    if (asked.status !== 200) throw Object.assign(new Error('check-in refused'), { word: `answered ${asked.status}` });
    const tokens = Array.isArray(asked.body?.instructions) ? asked.body.instructions.slice(0, MAX_INSTRUCTIONS) : [];
    const done = [];
    // Continual took the signature and not the time: say how far off this server's clock is, in this module's own words.
    const off = asked.body?.refused === 'clock' ? Number(asked.body.clock_off_s) : NaN;
    if (key && Number.isInteger(off) && Math.abs(off) <= 10 * 365 * 86400) {
      log(`continual-operator: this server's clock is ${clockOffWords(off)} Continual's, so Continual sent nothing; set the server's time`);
      done.push({ refused: 'clock', clock_off_s: off });
    }
    const report = (payload) => call(send, `${endpoint}/report`, { app: config.appId, module: MODULE_VERSION, ...payload }, signed('continual-report'));
    for (const token of tokens) {
      const v = await verifyInstruction(token, { appId: config.appId, keys, ops: [...Object.keys(OPERATIONS), ...Object.keys(MENU)], menu: allowed, seen, now: now(), subtle, appKid: key?.kid ?? null, limits });
      if (!v.ok) {
        // A refusal is reported only when the signature verified, so the nonce is Continual's own.
        if (v.nonce) await report({ nonce: v.nonce, refused: v.reason });
        done.push({ refused: v.reason });
        continue;
      }
      const { op, nonce, args } = v.instruction;
      if (MENU[op]) {
        const word = await runMenu(op, args);
        const sent = await report(word === 'done' ? { op, nonce, result: 'done' } : { nonce, refused: word });
        done.push({ op, nonce, result: word, reported: sent.status });
        continue;
      }
      const result = await OPERATIONS[op].run({ config, env, checks, tcp, fetch: send, now, args });
      const sent = await report({ op, nonce, report: result });
      done.push({ op, nonce, reported: sent.status });
    }
    return done;
  }

  /** The wrapper's call on each request. At most once per window in this copy; never rejects; one quiet line on a failure. */
  function tick() {
    try {
      if (switchedOff() || !config.appId || !keys.length || !subtle || typeof send !== 'function') return Promise.resolve(null);
      const t = now();
      if (t - last < config.checkinMinutes * 60_000) return lapse().then(() => null);
      last = t; // taken before the call, so requests arriving while it runs do not check in again
      return checkIn().catch((e) => { log(`continual-operator: check-in skipped (${quietWord(e)})`); return null; });
    } catch (e) {
      log(`continual-operator: check-in skipped (${quietWord(e)})`);
      return Promise.resolve(null);
    }
  }

  /**
   * Before a request goes on: null to carry on, or { status: 503, headers, body } — the maintenance page while it is up,
   * and, in read-only mode declared as "writes", the answer to a POST, PUT, PATCH or DELETE. Synchronous, with no call
   * out: it reads what this copy holds. Switched off, it holds nothing.
   */
  function hold({ method = 'GET', accept = '' } = {}) {
    if (switchedOff()) return null;
    const t = nowS();
    lapse(t); // runHook never rejects, so nothing here can fail the request
    const json = /application\/json/i.test(String(accept ?? ''));
    const answer = (kind, until, message) => ({
      status: 503,
      headers: { 'content-type': json ? 'application/json' : 'text/html; charset=utf-8', 'cache-control': 'no-store', 'retry-after': String(Math.max(1, until - t)) },
      body: json ? JSON.stringify({ error: kind, message }) : `<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${escapeHtml(message)}</title><body style="font:16px/1.5 system-ui,sans-serif;max-width:32rem;margin:20vh auto;padding:0 1rem"><p>${escapeHtml(message)}</p></body>`,
    });
    const mt = untilOf('maintenance', t);
    if (mt && config.menu.maintenance) return answer('maintenance', mt, config.menu.maintenance.message ?? 'This app is down for maintenance for a short while. Please try again soon.');
    const ro = untilOf('readonly', t);
    if (ro && config.menu.readonly?.refuse === 'writes' && WRITES.has(String(method).toUpperCase())) return answer('read_only', ro, 'This app is read-only for a short while, so nothing can be saved right now. Please try again soon.');
    return null;
  }

  return {
    tick, checkIn, config, hold,
    /** Whether this copy is in read-only mode now, for an app that refuses writes in its own code. */
    readOnly: () => !switchedOff() && !!untilOf('readonly'),
    /** Whether this copy is showing the maintenance page now. */
    maintenance: () => !switchedOff() && !!untilOf('maintenance'),
  };
}
