// Live check against the registered public endpoint, using the platform-issued secret.
import { createHmac } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';

const URL_ = process.env.AGENT_PUBLIC_URL || 'https://michelle-munich-outcomes-representative.trycloudflare.com';
const secret = JSON.parse(readFileSync(new URL('../config/secret.json', import.meta.url), 'utf8')).secret;
const sign = (b) => createHmac('sha256', secret).update(b).digest('hex');

const envelope = {
  type: 'agent-games.proof-gatekeeper.v1', task_id: 'live_' + Date.now(), mode: 'practice',
  issued_at: new Date().toISOString(), deadline_at: new Date(Date.now() + 60_000).toISOString(),
  input: {
    registered_vk: '0x7d3a0c5e91b4f8a2d6c1e0b7a948f3d2c510be64f7a1',
    proof_vk: '0x7d3a0c5e91b4f8a2d6c1e0b7a948f3d2c510be64f7a1',
    minimum: '1000', public_balance: '1460', expiry_block: 19842201, current_block: 19832000,
    recipient: '0xDe42a17c9b03f5e8d6a2c4b70f19e83d5a6c2b9f01',
    condition_recipient: '0xDe42a17c9b03f5e8d6a2c4b70f19e83d5a6c2b9f01',
    amount: '500', max_transfer: '1000', proof_tx: '0xlive' + Date.now(),
  },
};

const body = Buffer.from(JSON.stringify(envelope));
const t0 = Date.now();
const res = await fetch(`${URL_}/agent`, { method: 'POST', headers: { 'content-type': 'application/json', 'x-agent-games-signature': sign(body) }, body });
const text = await res.text();
const json = JSON.parse(text || '{}');
const respSig = res.headers.get('x-agent-games-signature');
const sigOk = respSig === createHmac('sha256', secret).update(Buffer.from(text)).digest('hex');

const unsigned = await fetch(`${URL_}/agent`, { method: 'POST', headers: { 'content-type': 'application/json' }, body });
const badJson = await unsigned.json().catch(() => ({}));

console.log(JSON.stringify({
  endpoint: URL_, status: res.status, ms: Date.now() - t0,
  decision: json.decision, reason: json.reason_code,
  proof: Boolean(json.proof), signals: (json.public_signals || []).length,
  response_signature_valid: sigOk,
  unsigned_rejected: unsigned.status === 401 && badJson.reason_code === 'BAD_SIGNATURE',
  unsigned_status: unsigned.status,
}, null, 1));

if (json.proof) {
  writeFileSync('/tmp/live-proof.json', JSON.stringify(json.proof));
  writeFileSync('/tmp/live-public.json', JSON.stringify(json.public_signals));
}
