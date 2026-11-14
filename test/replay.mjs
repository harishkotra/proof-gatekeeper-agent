// Offline replay harness: proves every trap class decides correctly AND that the
// Groth16 proof we emit verifies locally against the published vk.json.
// Run: node test/replay.mjs
import { createHmac } from 'node:crypto';
import { spawn } from 'node:child_process';
import { mkdtemp, rm, readFile, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.join(here, '..');
const CIRCUIT = path.join(root, 'circuits');
const SECRET = 'test-secret-' + Math.random().toString(36).slice(2);
const PORT = 8123 + Math.floor(Math.random() * 200);
const BASE = `http://127.0.0.1:${PORT}`;

const VK = '0x7d3a0c5e91b4f8a2d6c1e0b7a948f3d2c510be64f7a1';
const OTHER = '0xa4c1b8ff02e7d9c3a6f4b1e8d5c20793af64be01c8d2';
const RECIP = '0xDe42a17c9b03f5e8d6a2c4b70f19e83d5a6c2b9f01';
const RECIP2 = '0x9f01de42a17c9b03f5e8d6a2c4b70f19e83d5a6c2b';

const valid = (over = {}) => ({
  registered_vk: VK, proof_vk: VK, minimum: '1000', public_balance: '1460',
  expiry_block: 19842201, current_block: 19832000,
  recipient: RECIP, condition_recipient: RECIP, amount: '500', max_transfer: '1000',
  proof_tx: '0x' + Math.random().toString(16).slice(2).padEnd(64, '0'), ...over,
});

const CASES = [
  ['VALID_CONDITION (approve)', 'APPROVE', 'VALID_CONDITION', valid(), true],
  ['VK_SUBSTITUTION', 'REJECT', 'VK_SUBSTITUTION', valid({ proof_vk: OTHER }), true],
  ['THRESHOLD_MISMATCH', 'REJECT', 'THRESHOLD_MISMATCH', valid({ public_balance: '999' }), true],
  ['EXPIRED_CONDITION', 'REJECT', 'EXPIRED_CONDITION', valid({ current_block: 19842201 }), true],
  ['RECIPIENT_MISMATCH', 'REJECT', 'RECIPIENT_MISMATCH', valid({ recipient: RECIP2 }), true],
  ['AMOUNT_OVERFLOW', 'REJECT', 'AMOUNT_OVERFLOW', valid({ amount: '1001' }), true],
  ['at threshold / at cap (approve)', 'APPROVE', 'VALID_CONDITION', valid({ public_balance: '1000', amount: '1000' }), true],
];

const hmac = (buf, secret = SECRET) => createHmac('sha256', secret).update(buf).digest('hex');

async function post(envelope, { secret = SECRET, type } = {}) {
  const body = Buffer.from(JSON.stringify(type ? { ...envelope, type } : envelope));
  const res = await fetch(`${BASE}/agent`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'x-agent-games-signature': hmac(body, secret) },
    body,
  });
  const text = await res.text();
  return { status: res.status, headers: res.headers, text, json: JSON.parse(text || '{}'), raw: body };
}

async function verifyProof(proof, publicSignals) {
  const snarkjs = await import('snarkjs');
  const vk = JSON.parse(await readFile(path.join(CIRCUIT, 'vk.json'), 'utf8'));
  try {
    return await snarkjs.groth16.verify(vk, publicSignals, proof);
  } catch (e) {
    console.log('   verify threw:', String(e.message || e).slice(0, 120));
    return false;
  }
}

const server = spawn('node', [path.join(root, 'src', 'server.mjs')], {
  env: { ...process.env, PORT: String(PORT), AGENT_GAMES_HMAC_SECRET: SECRET, AUDIT_LOG: path.join(tmpdir(), 'audit-test.jsonl'), SEEN_SET_FILE: path.join(tmpdir(), 'seen-test.json') },
  stdio: ['ignore', 'pipe', 'pipe'],
});
server.stderr.on('data', (d) => process.stderr.write('[server] ' + d));

const wait = (ms) => new Promise((r) => setTimeout(r, ms));
let failures = 0;
const line = (ok, label, detail = '') => {
  if (!ok) failures += 1;
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${label}${detail ? ' - ' + detail : ''}`);
};

try {
  for (let i = 0; i < 60; i++) {
    try { if ((await fetch(`${BASE}/health`)).ok) break; } catch { await wait(200); }
  }

  // Preflight
  const pf = await post({ type: 'agent-games.preflight.v1', agent_id: 'agt_test', issued_at: new Date().toISOString(), nonce: 'abc123' });
  const pfSigOk = pf.headers.get('x-agent-games-signature') === hmac(Buffer.from(pf.text));
  line(pf.json.ok === true && pf.json.protocolVersion === 'v1' && pfSigOk, 'preflight handshake', JSON.stringify(pf.json));

  // Bad signature must be refused
  const bad = await post(valid(), { secret: 'wrong' });
  line(bad.status === 401, 'unsigned/wrong-signature task refused', `status ${bad.status}`);

  for (const [label, wantDecision, wantReason, input, wantProof] of CASES) {
    const envelope = {
      type: 'agent-games.proof-gatekeeper.v1', task_id: 'gk_test_' + label.replace(/\W+/g, '_'),
      mode: 'practice', issued_at: new Date().toISOString(),
      deadline_at: new Date(Date.now() + 60_000).toISOString(), input,
    };
    const r = await post(envelope);
    const sigOk = r.headers.get('x-agent-games-signature') === hmac(Buffer.from(r.text));
    const okDecision = r.json.decision === wantDecision && r.json.reason_code === wantReason;
    const hasProof = Boolean(r.json.proof && r.json.public_signals);
    let proofOk = true;
    if (hasProof) proofOk = await verifyProof(r.json.proof, r.json.public_signals);
    const ok = okDecision && sigOk && (hasProof === wantProof) && proofOk;
    line(ok, label, `${r.json.decision}/${r.json.reason_code} proof=${hasProof} verified=${proofOk} sig=${sigOk}`);
  }

  // Reuse: same proof_tx twice -> second is PROOF_REUSED with no proof.
  const reuseInput = valid({ proof_tx: '0xdeadbeef' + '0'.repeat(56) });
  const e1 = { type: 'agent-games.proof-gatekeeper.v1', task_id: 'gk_reuse_1', mode: 'practice', issued_at: new Date().toISOString(), deadline_at: new Date(Date.now() + 60000).toISOString(), input: reuseInput };
  await post(e1);
  const e2 = { ...e1, task_id: 'gk_reuse_2' };
  const r2 = await post(e2);
  line(r2.json.decision === 'REJECT' && r2.json.reason_code === 'PROOF_REUSED' && !r2.json.proof,
    'PROOF_REUSED on second sighting', JSON.stringify({ d: r2.json.decision, r: r2.json.reason_code, proof: Boolean(r2.json.proof) }));

  // Expired deadline fails closed.
  const stale = await post({ type: 'agent-games.proof-gatekeeper.v1', task_id: 'gk_stale', mode: 'practice', issued_at: new Date().toISOString(), deadline_at: new Date(Date.now() - 5000).toISOString(), input: valid() });
  line(stale.json.decision === 'REJECT', 'past-deadline task rejected', stale.json.reason_code);

  console.log(failures === 0 ? '\nALL CHECKS PASSED' : `\n${failures} CHECK(S) FAILED`);
} finally {
  server.kill('SIGTERM');
  await wait(150);
  process.exit(failures === 0 ? 0 : 1);
}
