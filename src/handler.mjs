// Shared request handler - used by both the long-lived server and the serverless function.
import { createHmac, timingSafeEqual } from 'node:crypto';
import { appendFile } from 'node:fs/promises';
import { readFileSync } from 'node:fs';
import { decide, buildSignals, REASON } from './decide.mjs';
import { prove, proverStats } from './prover.mjs';
import { createStore } from './store.mjs';

function loadSecret() {
  if (process.env.AGENT_GAMES_HMAC_SECRET) return process.env.AGENT_GAMES_HMAC_SECRET;
  // Fallback for anonymous/temporary deployments where env vars are unavailable.
  for (const p of ['../config/secret.json', './config/secret.json', process.cwd() + '/config/secret.json']) {
    try {
      const j = JSON.parse(readFileSync(new URL(p, import.meta.url), 'utf8'));
      if (j.secret) return String(j.secret);
    } catch { /* try next */ }
  }
  return '';
}
const SECRET = loadSecret();
const SIG_HEADER = 'x-agent-games-signature';
const ENCODING = (process.env.SIGNATURE_ENCODING || 'hex').toLowerCase();
const MAX_BODY = 256 * 1024;
const AUDIT = process.env.AUDIT_LOG || './data/audit.jsonl';

let _store = null;
const store = () => (_store ||= createStore());

const hmac = (data) => createHmac('sha256', SECRET).update(data).digest(ENCODING);
const safeEqual = (a, b) => {
  const A = Buffer.from(String(a || ''), 'utf8'), B = Buffer.from(String(b || ''), 'utf8');
  return A.length === B.length && A.length > 0 && timingSafeEqual(A, B);
};

function readRaw(req) {
  if (typeof req.body === 'object' && req.body !== null) {
    // serverless runtimes may pre-parse; re-serialise is NOT safe for HMAC, so prefer raw
    if (Buffer.isBuffer(req.rawBody)) return Promise.resolve(req.rawBody);
  }
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    req.on('data', (c) => {
      size += c.length;
      if (size > MAX_BODY) { reject(new Error('body too large')); req.destroy(); return; }
      chunks.push(c);
    });
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

async function audit(entry) {
  try { await appendFile(AUDIT, JSON.stringify(entry) + '\n'); } catch { /* logging never fails a task */ }
}

function send(res, status, obj) {
  const body = Buffer.from(JSON.stringify(obj), 'utf8');
  const headers = { 'content-type': 'application/json', 'content-length': body.length };
  if (SECRET) headers[SIG_HEADER] = hmac(body);
  res.writeHead(status, headers);
  res.end(body);
  return body;
}

function verifySignature(raw, header) {
  if (!SECRET) return { ok: true, skipped: true };
  if (!header) return { ok: false, why: 'missing signature header' };
  const expected = hmac(raw);
  if (safeEqual(header, expected)) return { ok: true };
  if (safeEqual(String(header).toLowerCase(), expected.toLowerCase())) return { ok: true };
  return { ok: false, why: 'signature mismatch' };
}

export async function handle(req, res) {
  const t0 = Date.now();
  const url = new URL(req.url || '/', 'http://localhost');

  if (req.method === 'GET' && (url.pathname === '/health' || url.pathname === '/' || url.pathname === '/api/health')) {
    return send(res, 200, { ok: true, service: 'proof-gatekeeper', uptime_s: Math.round(process.uptime()), prover: proverStats(), seen: store().size?.() ?? 0 });
  }
  // Any POST is a task: hosts rewrite /agent to /api/agent and hand us the rewritten path.
  if (req.method !== 'POST') {
    return send(res, 404, { error: 'not found' });
  }

  let raw;
  try { raw = await readRaw(req); } catch (e) { return send(res, 413, { error: e.message }); }

  const sig = verifySignature(raw, req.headers[SIG_HEADER]);
  if (!sig.ok) {
    await audit({ at: new Date().toISOString(), outcome: 'bad_signature', why: sig.why, bytes: raw.length });
    return send(res, 401, { decision: 'REJECT', reason_code: REASON.BAD_SIGNATURE });
  }

  let envelope;
  try { envelope = JSON.parse(raw.toString('utf8')); }
  catch {
    await audit({ at: new Date().toISOString(), outcome: 'bad_json' });
    return send(res, 400, { decision: 'REJECT', reason_code: REASON.MALFORMED });
  }

  if (envelope?.type === 'agent-games.preflight.v1') {
    await audit({ at: new Date().toISOString(), outcome: 'preflight', agent_id: envelope.agent_id, nonce: envelope.nonce });
    return send(res, 200, { ok: true, protocolVersion: 'v1' });
  }

  if (envelope?.type !== 'agent-games.proof-gatekeeper.v1') {
    await audit({ at: new Date().toISOString(), outcome: 'unknown_type', type: envelope?.type });
    return send(res, 200, { decision: 'REJECT', reason_code: REASON.MALFORMED });
  }

  const input = envelope.input || {};
  const ref = String(input.proof_tx ?? '').trim().toLowerCase();
  await store().load?.();
  const verdict = decide(input, { now: Date.now(), deadlineAt: envelope.deadline_at, seen: store() });

  let proof = null, publicSignals = null, proofError = null;
  if (verdict.needProof) {
    try {
      const out = await prove(buildSignals(input, verdict.decision, envelope.task_id));
      proof = out.proof;
      publicSignals = out.publicSignals;
    } catch (err) {
      proofError = String(err.message || err).slice(0, 200);
      if (verdict.decision === 'APPROVE') {
        verdict.decision = 'REJECT';
        verdict.reason_code = REASON.THRESHOLD;
      }
    }
  }

  if (ref && verdict.reason_code !== REASON.REUSED) await store().add(ref).catch(() => {});

  const body = { decision: verdict.decision, reason_code: verdict.reason_code };
  if (proof) { body.proof = proof; body.public_signals = publicSignals; }
  if (input.proof_tx) body.proof_tx = input.proof_tx;

  await audit({
    at: new Date().toISOString(), task_id: envelope.task_id, mode: envelope.mode,
    decision: body.decision, reason_code: body.reason_code, proved: Boolean(proof),
    ms: Date.now() - t0, proof_error: proofError, proof_tx: input.proof_tx ?? null,
  });

  return send(res, 200, body);
}
