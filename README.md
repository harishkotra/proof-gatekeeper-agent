# Proof Gatekeeper — zkVerify Agent Games

A deterministic payment-gatekeeper agent that decides APPROVE/REJECT on a signed
condition envelope and writes its own Groth16 proof of that decision.

Built for the [zkVerify Agent Games](https://agentgames.zkverify.io/) **Proof Gatekeeper**
event (Groth16/BN128, `gatekeeper.wasm`, 13 public signals, 8 daily scored rounds).

## Why this beats a vibecoded harness

The circuit does not decide anything — it *refuses to let you lie*. Every rule below is
enforced by the R1CS, verified empirically against the published artifacts:

| Rule | Enforced | Boundary found by experiment |
|---|---|---|
| `proof_vk == registered_vk` | assert in circuit | any mismatch → `WITNESS_FAIL` |
| `current_block < expiry_block` | assert in circuit | equal heights already fail (strict) |
| `recipient == condition_recipient` | assert in circuit | case-insensitive hex compare |
| `amount <= max_transfer` | assert in circuit | equal to cap is allowed |
| `public_balance >= minimum` | assert in circuit | equal to minimum is allowed |
| `proof_tx` not seen before | **off-circuit** | must be tracked by the agent |
| signature + deadline | **off-circuit** | HMAC over raw body, fail closed |

Two consequences that decide the score:

1. A REJECT is always provable (`decision = 0` satisfies the circuit), so every trap gets a
   real proof and keeps the reliability bonus. Only `PROOF_REUSED` is exempt — the platform
   excludes it from the bonus and there is nothing to prove.
2. The agent must never emit an APPROVE it cannot prove. If proving fails, the decision is
   downgraded to REJECT inside the handler (fail closed), never sent unproven.

## Reverse-engineered circuit interface

13 public signals, discovered from `gatekeeper.wasm` (the names are published nowhere):

```
salt*  taskId  registeredVkHash  proofVkHash  minimum  publicBalance
expiryBlock  currentBlock  recipient  conditionRecipient  amount  maxTransfer  decision
```

`salt` is a private blinding input; the public commitment is derived from it.
Non-numeric values (addresses, `task_id`) are mapped to BN254 field elements
deterministically (`0x` hex and decimal pass through, everything else is SHA-256 reduced mod p).

## Layout

```
src/decide.mjs    pure policy engine (no I/O, no model) + signal builder
src/prover.mjs    serialised Groth16 proving, one job at a time
src/store.mjs     durable seen-set (file, or GitHub-backed for serverless)
src/handler.mjs   HMAC verify → decide → prove → sign, shared by server and function
src/server.mjs    long-lived HTTP server
api/agent.mjs     serverless entry (Vercel)
test/replay.mjs   all 7 trap classes + reuse + stale + signature, each proof verified
test/load.mjs     16 concurrent provable tasks
```

## Run

```bash
npm install
cp .env.example .env      # set AGENT_GAMES_HMAC_SECRET
node src/server.mjs       # or: npm start
```

```bash
npm test        # replays every trap class, verifies each Groth16 proof locally
node test/load.mjs
```

## Endpoint contract

- `POST /agent` — signed task envelope in, `{decision, reason_code, proof, public_signals, proof_tx}` out,
  every response carrying `x-agent-games-signature` over the raw body.
- `GET /health` — liveness for the platform health check.
- Preflight (`agent-games.preflight.v1`) answers `{ok:true, protocolVersion:"v1"}`, signed.

## Deploy

Serverless (Vercel): `vercel --prod`. Circuits ship with the function via `includeFiles`.
For durable reuse tracking on serverless set `SEEN_SET_BACKEND=github` plus
`GITHUB_TOKEN`, `SEEN_SET_REPO` (a private repo). Container: `docker build -t gatekeeper . && docker run -p 8080:8080 --env-file .env gatekeeper`.

## Measured

- proof + verify per task: **~80 ms**
- 16 concurrent provable tasks: **861 ms wall**, slowest 856 ms (limit is 60 s)
- 11/11 replay checks pass, every emitted proof verified against `vk.json`

## Security

Secrets come from the environment only; `.env` is gitignored. Inbound HMAC is checked
over the raw body before JSON parsing. Any error path returns REJECT.
