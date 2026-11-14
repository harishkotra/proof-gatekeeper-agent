// Deterministic policy engine for Proof Gatekeeper.
// The circuit is the referee: APPROVE is only provable when every rule holds.
// Verified empirically against gatekeeper.wasm (see test/replay.mjs).
import { createHash } from 'node:crypto';

export const REASON = {
  VALID: 'VALID_CONDITION',
  VK: 'VK_SUBSTITUTION',
  THRESHOLD: 'THRESHOLD_MISMATCH',
  REUSED: 'PROOF_REUSED',
  EXPIRED: 'EXPIRED_CONDITION',
  RECIPIENT: 'RECIPIENT_MISMATCH',
  OVERFLOW: 'AMOUNT_OVERFLOW',
  BAD_SIGNATURE: 'BAD_SIGNATURE',
  STALE: 'STALE_TASK',
  MALFORMED: 'MALFORMED_TASK',
};

const FIELD_PRIME = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;

/** Map any payload value to a BN254 field element deterministically. */
export function toField(value) {
  if (typeof value === 'bigint') return value % FIELD_PRIME;
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) throw new Error('non-finite number');
    return BigInt(Math.trunc(value)) % FIELD_PRIME;
  }
  if (typeof value === 'boolean') return value ? 1n : 0n;
  const s = String(value ?? '').trim();
  if (s === '') throw new Error('empty value');
  if (/^\d+$/.test(s)) return BigInt(s) % FIELD_PRIME;
  if (/^0x[0-9a-fA-F]+$/.test(s)) return BigInt(s) % FIELD_PRIME;
  const h = createHash('sha256').update(s.toLowerCase()).digest('hex');
  return BigInt('0x' + h) % FIELD_PRIME;
}

/** Address comparison that tolerates case and 0x-prefix differences. */
function sameAddress(a, b) {
  const norm = (v) => String(v ?? '').trim().toLowerCase().replace(/^0x/, '');
  return norm(a) === norm(b) && norm(a).length > 0;
}

/**
 * Pure decision function. No I/O, no model, no clock beyond `now`.
 * Returns { decision, reason_code, needProof }.
 */
export function decide(input, { now = Date.now(), deadlineAt = null, seen = null } = {}) {
  const i = input ?? {};

  // 0. Deadline: a task that already expired is not answerable.
  if (deadlineAt) {
    const dl = Date.parse(deadlineAt);
    if (Number.isFinite(dl) && now > dl) return { decision: 'REJECT', reason_code: REASON.STALE, needProof: false };
  }

  const fields = ['registered_vk', 'proof_vk', 'minimum', 'public_balance', 'recipient', 'condition_recipient', 'amount', 'max_transfer'];
  for (const f of fields) {
    if (i[f] === undefined || i[f] === null) return { decision: 'REJECT', reason_code: REASON.MALFORMED, needProof: false };
  }
  if (i.expiry_block === undefined || i.current_block === undefined) {
    return { decision: 'REJECT', reason_code: REASON.MALFORMED, needProof: false };
  }

  // 1. VK substitution: the proof's key must be the key registered for this condition.
  if (!sameAddress(i.proof_vk, i.registered_vk)) {
    return { decision: 'REJECT', reason_code: REASON.VK, needProof: true };
  }

  // 2. Reuse: this proof reference was already accepted. Nothing to prove - excluded from reliability.
  const ref = String(i.proof_tx ?? '').trim().toLowerCase();
  if (ref && seen && seen.has(ref)) {
    return { decision: 'REJECT', reason_code: REASON.REUSED, needProof: false };
  }

  // 3. Expiry: current block must be strictly before the expiry height.
  const currentBlock = BigInt(String(i.current_block));
  const expiryBlock = BigInt(String(i.expiry_block));
  if (currentBlock >= expiryBlock) {
    return { decision: 'REJECT', reason_code: REASON.EXPIRED, needProof: true };
  }

  // 4. Recipient: the committed recipient must be the condition's payee.
  if (!sameAddress(i.recipient, i.condition_recipient)) {
    return { decision: 'REJECT', reason_code: REASON.RECIPIENT, needProof: true };
  }

  // 5. Amount cap: single transfer must not exceed the cap.
  const amount = BigInt(String(i.amount));
  const maxTransfer = BigInt(String(i.max_transfer));
  if (amount < 0n || amount > maxTransfer) {
    return { decision: 'REJECT', reason_code: REASON.OVERFLOW, needProof: true };
  }

  // 6. Threshold: disclosed balance must meet the minimum.
  const balance = BigInt(String(i.public_balance));
  const minimum = BigInt(String(i.minimum));
  if (balance < minimum) {
    return { decision: 'REJECT', reason_code: REASON.THRESHOLD, needProof: true };
  }

  return { decision: 'APPROVE', reason_code: REASON.VALID, needProof: true };
}

/** Build the 13-signal witness for gatekeeper.wasm. decision: 1 = APPROVE. */
export function buildSignals(input, decision, taskId) {
  const saltSrc = `${taskId ?? ''}|${input?.proof_tx ?? ''}|${input?.registered_vk ?? ''}`;
  const salt = toField('salt:' + saltSrc);
  return {
    salt: salt.toString(),
    taskId: toField(taskId ?? 'unknown').toString(),
    registeredVkHash: toField(input.registered_vk).toString(),
    proofVkHash: toField(input.proof_vk).toString(),
    minimum: toField(input.minimum).toString(),
    publicBalance: toField(input.public_balance).toString(),
    expiryBlock: toField(input.expiry_block).toString(),
    currentBlock: toField(input.current_block).toString(),
    recipient: toField(input.recipient).toString(),
    conditionRecipient: toField(input.condition_recipient).toString(),
    amount: toField(input.amount).toString(),
    maxTransfer: toField(input.max_transfer).toString(),
    decision: decision === 'APPROVE' ? '1' : '0',
  };
}
