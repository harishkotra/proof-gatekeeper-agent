import { proverStats } from '../src/prover.mjs';

export default function (req, res) {
  res.status(200).json({
    ok: true,
    service: 'proof-gatekeeper',
    uptime_s: Math.round(process.uptime()),
    prover: proverStats(),
  });
}
