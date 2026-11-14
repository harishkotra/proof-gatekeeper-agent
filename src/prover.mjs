// Local Groth16 proving for gatekeeper.wasm (Groth16/BN128, 13 public signals).
// Serialised: one proof at a time, bounded queue, so parallel tasks cannot thrash memory.
import * as snarkjs from 'snarkjs';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
export const CIRCUIT_DIR = process.env.CIRCUIT_DIR || path.join(here, '..', 'circuits');
const WASM = path.join(CIRCUIT_DIR, 'gatekeeper.wasm');
const ZKEY = path.join(CIRCUIT_DIR, 'gatekeeper_final.zkey');

let chain = Promise.resolve();
let served = 0;
let failed = 0;

/** Queue a proof job; resolves { proof, publicSignals } or throws. */
export function prove(signals) {
  const run = chain.then(() => proveNow(signals));
  chain = run.then(() => {}, () => {});
  return run;
}

async function proveNow(signals) {
  const dir = await mkdtemp(path.join(tmpdir(), 'gk-'));
  const inFile = path.join(dir, 'input.json');
  const wtnsFile = path.join(dir, 'w.wtns');
  try {
    await writeFile(inFile, JSON.stringify(signals));
    await snarkjs.wtns.calculate(signals, WASM, wtnsFile);
    const { proof, publicSignals } = await snarkjs.groth16.prove(ZKEY, wtnsFile);
    served += 1;
    return { proof, publicSignals };
  } catch (err) {
    failed += 1;
    throw err;
  } finally {
    await rm(dir, { recursive: true, force: true }).catch(() => {});
  }
}

export function proverStats() {
  return { served, failed };
}
