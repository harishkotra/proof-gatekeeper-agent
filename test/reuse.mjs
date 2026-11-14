// Proves PROOF_REUSED works across serverless instances: same proof_tx twice.
import { createHmac } from 'node:crypto';
import { readFileSync } from 'node:fs';

const URL_ = process.env.AGENT_PUBLIC_URL || 'https://agent-virid-psi.vercel.app';
const secret = JSON.parse(readFileSync(new URL('../config/secret.json', import.meta.url), 'utf8')).secret;
const sign = (b) => createHmac('sha256', secret).update(b).digest('hex');

const proofTx = '0xreuse' + Date.now().toString(16);
const mk = (id) => Buffer.from(JSON.stringify({
  type: 'agent-games.proof-gatekeeper.v1', task_id: id, mode: 'practice',
  issued_at: new Date().toISOString(), deadline_at: new Date(Date.now() + 60_000).toISOString(),
  input: {
    registered_vk: '0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0',
    proof_vk: '0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0',
    minimum: '1000', public_balance: '1460', expiry_block: 8430000, current_block: 8420000,
    recipient: '0xabcdef1234567890abcdef1234567890abcdef12',
    condition_recipient: '0xabcdef1234567890abcdef1234567890abcdef12',
    amount: '500', max_transfer: '1000', proof_tx: proofTx,
  },
}));

const post = async (id) => {
  const body = mk(id);
  const res = await fetch(`${URL_}/agent`, { method: 'POST', headers: { 'content-type': 'application/json', 'x-agent-games-signature': sign(body) }, body });
  const j = await res.json().catch(() => ({}));
  return { status: res.status, decision: j.decision, reason: j.reason_code, proof: Boolean(j.proof), signals: (j.public_signals || []).length };
};

const first = await post('reuse_a_' + Date.now());
await new Promise((r) => setTimeout(r, 1200)); // let the write land
const second = await post('reuse_b_' + Date.now());
await new Promise((r) => setTimeout(r, 400));
const third = await post('reuse_c_' + Date.now()); // third = fresh instance view again

console.log(JSON.stringify({ endpoint: URL_, proof_tx: proofTx, first, second, third,
  reuse_held: second.reason === 'PROOF_REUSED' && third.reason === 'PROOF_REUSED',
  first_approved: first.decision === 'APPROVE' && first.proof === true }, null, 1));
