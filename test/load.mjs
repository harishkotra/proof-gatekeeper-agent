// Load check: 16 concurrent provable tasks must all answer well inside the 60s window.
import { createHmac } from 'node:crypto';
import { spawn } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.join(here, '..');
const SECRET = 'load-secret';
const PORT = 8411;
const BASE = `http://127.0.0.1:${PORT}`;
const hmac = (b) => createHmac('sha256', SECRET).update(b).digest('hex');
const VK = '0x7d3a0c5e91b4f8a2d6c1e0b7a948f3d2c510be64f7a1';

const input = (n) => ({
  registered_vk: VK, proof_vk: VK, minimum: '1000', public_balance: '1460',
  expiry_block: 19842201, current_block: 19832000,
  recipient: '0xDe42a17c9b03f5e8d6a2c4b70f19e83d5a6c2b9f01',
  condition_recipient: '0xDe42a17c9b03f5e8d6a2c4b70f19e83d5a6c2b9f01',
  amount: '500', max_transfer: '1000', proof_tx: '0xload' + n.toString().padStart(60, '0'),
});

const srv = spawn('node', [path.join(root, 'src', 'server.mjs')], {
  env: { ...process.env, PORT: String(PORT), AGENT_GAMES_HMAC_SECRET: SECRET, SEEN_SET_FILE: '/tmp/seen-load.json', AUDIT_LOG: '/tmp/audit-load.jsonl' },
  stdio: ['ignore', 'ignore', 'inherit'],
});
const wait = (ms) => new Promise((r) => setTimeout(r, ms));

try {
  for (let i = 0; i < 50; i++) { try { if ((await fetch(`${BASE}/health`)).ok) break; } catch { await wait(150); } }
  const N = 16;
  const t0 = Date.now();
  const results = await Promise.all([...Array(N)].map(async (_, i) => {
    const body = Buffer.from(JSON.stringify({
      type: 'agent-games.proof-gatekeeper.v1', task_id: 'load_' + i, mode: 'load',
      issued_at: new Date().toISOString(), deadline_at: new Date(Date.now() + 60_000).toISOString(), input: input(i),
    }));
    const s = Date.now();
    const res = await fetch(`${BASE}/agent`, { method: 'POST', headers: { 'content-type': 'application/json', 'x-agent-games-signature': hmac(body) }, body });
    const j = await res.json();
    return { ms: Date.now() - s, ok: j.decision === 'APPROVE' && Boolean(j.proof), reason: j.reason_code };
  }));
  const wall = Date.now() - t0;
  const ok = results.filter((r) => r.ok).length;
  const slowest = Math.max(...results.map((r) => r.ms));
  console.log(JSON.stringify({ tasks: N, approved_with_proof: ok, wall_ms: wall, slowest_ms: slowest, all_under_60s: slowest < 60000 }, null, 0));
  process.exitCode = ok === N ? 0 : 1;
} finally {
  srv.kill('SIGTERM');
  await wait(100);
}
