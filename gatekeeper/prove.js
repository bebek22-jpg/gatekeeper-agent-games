'use strict';
// Standalone proving CLI for the Gatekeeper circuit.
//
// Usage:
//   node prove.js <input.json> [--verify]
//
// The input file may be either:
//   a) a raw 13-signal circuit input (all of registeredVkHash, proofVkHash,
//      minimum, publicBalance, expiryBlock, currentBlock, recipient,
//      conditionRecipient, amount, maxTransfer, decision, taskId, salt) —
//      used as-is, or
//   b) a task envelope (as the platform would POST) — fields are extracted,
//      the decision is computed with the same rules as server.js, and the
//      circuit input is built from it.
//
// Prints { decision, proof, publicSignals, taskId, proveMs } as JSON to
// stdout. With --verify, also verifies the proof against
// circuits/verification_key.json and adds "verified": true/false.
// Exit code 0 on success, 1 on any failure (error on stderr).

const fs = require('fs');

let snarkjs;
try {
  snarkjs = require('snarkjs');
} catch {
  snarkjs = require('../node_modules/snarkjs');
}

const {
  WASM_PATH,
  ZKEY_PATH,
  VK_PATH,
  extractFields,
  decide,
  buildCircuitInput,
  isDirectCircuitInput,
  normalizeDirectInput,
} = require('./input');

async function main() {
  const args = process.argv.slice(2).filter((a) => a !== '--verify');
  const doVerify = process.argv.includes('--verify');
  if (args.length !== 1) {
    console.error('usage: node prove.js <input.json> [--verify]');
    process.exit(1);
  }

  let data;
  try {
    data = JSON.parse(fs.readFileSync(args[0], 'utf8'));
  } catch (err) {
    console.error(`cannot read/parse ${args[0]}: ${err.message}`);
    process.exit(1);
  }

  let input;
  let decision;
  let taskId = null;

  if (isDirectCircuitInput(data)) {
    const norm = normalizeDirectInput(data);
    if (norm.error) {
      console.error(norm.error);
      process.exit(1);
    }
    input = norm.input;
    decision = Number(input.decision);
    taskId = input.taskId;
  } else {
    const fields = extractFields(data);
    taskId = fields.taskId !== undefined && fields.taskId !== null ? fields.taskId : null;
    const verdict = decide(fields);
    decision = verdict.decision;
    if (decision === 0) {
      console.error(`decision 0 (${verdict.reasons.join('; ')}) — proving decision 0`);
    }
    const built = buildCircuitInput(fields, decision);
    if (built.error) {
      console.error(built.error);
      process.exit(1);
    }
    input = built.input;
  }

  const started = Date.now();
  let result;
  try {
    result = await snarkjs.groth16.fullProve(input, WASM_PATH, ZKEY_PATH);
  } catch (err) {
    console.error(`PROVE_FAIL: ${err && err.message ? err.message : err}`);
    process.exit(1);
  }
  const proveMs = Date.now() - started;

  const out = {
    decision,
    proof: result.proof,
    publicSignals: result.publicSignals.map(String),
    taskId,
    proveMs,
  };

  if (doVerify) {
    const vk = JSON.parse(fs.readFileSync(VK_PATH, 'utf8'));
    out.verified = await snarkjs.groth16.verify(
      vk,
      result.publicSignals,
      result.proof,
    );
  }

  console.log(JSON.stringify(out));

  // snarkjs leaves worker threads (MessagePorts) alive after proving, so
  // the process would never exit on its own. Workers are reused across
  // proves (no accumulation), so exiting explicitly here is safe.
  process.exit(0);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
