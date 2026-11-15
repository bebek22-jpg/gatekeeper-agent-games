'use strict';
// Local end-to-end test for server.js. No extra deps; localhost only.
//
// Spawns the server (port 3102, so it never clashes with a live instance on
// 3101) with a DUMMY secret, then runs the real /build-schema cases:
//   1. GET /health                       -> {"ok":true}
//   2. preflight envelope                -> {ok:true, protocolVersion:"v1"}, signed
//   3. valid real-schema envelope        -> 200, APPROVE/VALID_CONDITION,
//      proof present, 13 public_signals, proof_tx echoed, response
//      signature verifies, proof verifies against the vk
//   4. wrong HMAC                        -> 401
//   5. missing signature                 -> 401
//   6. VK_SUBSTITUTION trap              -> REJECT + proof
//   7. THRESHOLD_MISMATCH trap           -> REJECT + proof
//   8. RECIPIENT_MISMATCH trap           -> REJECT + proof
//   9. AMOUNT_EXCEEDED trap              -> REJECT + proof
//  10. EXPIRED trap                      -> REJECT + proof
//  11. missing fields                    -> REJECT/INVALID_INPUT, no proof
//  12. legacy flat envelope (camelCase)  -> still APPROVE (backward compat)
//
// Usage: node test_local.js
// Exit code 0 when all cases pass.

const http = require('http');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { spawn } = require('child_process');

let snarkjs;
try {
  snarkjs = require('snarkjs');
} catch {
  snarkjs = require('../node_modules/snarkjs');
}
const { VK_PATH } = require('./input');

const PORT = 3102;
const SECRET = 'testsecret123';
const BASE = `http://127.0.0.1:${PORT}`;

const VK_HEX = '0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0';
const VK_OTHER = '0x6c56509f1c56fd1fd4e9737f906d2220f4b95f1d507f1adf6899085bd74be047'; // vfyPolicy vk
const RECIPIENT_HEX = '0x1111111111111111111111111111111111111111';
const OTHER_HEX = '0x2222222222222222222222222222222222222222';
const PROOF_TX = '0xa8b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a8b2';

// Real /build schema envelope, with MIXED formats to exercise
// normalization (numbers, decimal strings, hex strings).
function validEnvelope(inputOverrides = {}) {
  return {
    type: 'agent-games.proof-gatekeeper.v1',
    task_id: 'gk_8d31_test1',
    mode: 'competition',
    issued_at: '2026-11-15T02:00:00Z',
    deadline_at: '2026-11-15T02:01:00Z',
    input: {
      registered_vk: VK_HEX,
      proof_vk: VK_HEX,
      minimum: '1000',
      public_balance: 1460,
      expiry_block: 8430000,
      current_block: '8420000',
      recipient: RECIPIENT_HEX,
      condition_recipient: RECIPIENT_HEX,
      amount: '500',
      max_transfer: 1000,
      proof_tx: PROOF_TX,
      ...inputOverrides,
    },
  };
}

function hmacHex(bodyBuf, secret = SECRET) {
  return crypto.createHmac('sha256', secret).update(bodyBuf).digest('hex');
}

function request({ method, path: p, body, headers = {} }) {
  return new Promise((resolve, reject) => {
    const req = http.request(
      { host: '127.0.0.1', port: PORT, path: p, method, headers },
      (res) => {
        const chunks = [];
        res.on('data', (c) => chunks.push(c));
        res.on('end', () =>
          resolve({
            status: res.statusCode,
            headers: res.headers,
            raw: Buffer.concat(chunks),
          }),
        );
      },
    );
    req.on('error', reject);
    if (body) req.write(body);
    req.end();
  });
}

async function postEnvelope(envelope, { secret = SECRET, sign = true, path: p = '/task' } = {}) {
  const body = Buffer.from(JSON.stringify(envelope), 'utf8');
  const headers = { 'Content-Type': 'application/json' };
  if (sign) headers['x-agent-games-signature'] = hmacHex(body, secret);
  return request({ method: 'POST', path: p, body, headers });
}

function verifyResponseSignature(res) {
  const sig = res.headers['x-agent-games-signature'];
  if (!sig) return false;
  return crypto.timingSafeEqual(
    Buffer.from(hmacHex(res.raw), 'hex'),
    Buffer.from(sig.replace(/^sha256=/, ''), 'hex'),
  );
}

async function waitForHealth(timeoutMs = 15_000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      const res = await request({ method: 'GET', path: '/health' });
      if (res.status === 200) return true;
    } catch {
      // not up yet
    }
    await new Promise((r) => setTimeout(r, 200));
  }
  return false;
}

const results = [];
function check(name, ok, detail = '') {
  results.push({ name, ok, detail });
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${detail ? ` — ${detail}` : ''}`);
}

async function main() {
  const server = spawn(
    process.execPath,
    [path.join(__dirname, 'server.js')],
    {
      env: { ...process.env, PORT: String(PORT), HMAC_SECRET: SECRET },
      stdio: ['ignore', 'pipe', 'pipe'],
    },
  );
  let serverLog = '';
  server.stdout.on('data', (d) => (serverLog += d));
  server.stderr.on('data', (d) => (serverLog += d));

  const cleanup = () => {
    try {
      server.kill('SIGTERM');
    } catch {
      // already dead
    }
  };
  process.on('exit', cleanup);

  if (!(await waitForHealth())) {
    console.error('server did not come up:\n' + serverLog);
    process.exit(1);
  }

  // --- 1: health ---
  {
    const res = await request({ method: 'GET', path: '/health' });
    const body = JSON.parse(res.raw.toString('utf8'));
    check('GET /health returns {"ok":true}', res.status === 200 && body.ok === true);
  }

  // --- 2: preflight ---
  {
    const res = await postEnvelope({
      type: 'agent-games.preflight.v1',
      agent_id: 'agt_test',
      issued_at: '2026-11-15T02:00:00Z',
      nonce: 'abc123',
    });
    const body = JSON.parse(res.raw.toString('utf8'));
    check(
      'preflight -> {ok:true, protocolVersion:"v1"}, signed',
      res.status === 200 && body.ok === true && body.protocolVersion === 'v1' && verifyResponseSignature(res),
      `status=${res.status} body=${res.raw.toString('utf8').slice(0, 80)}`,
    );
  }

  // --- 3: valid envelope, correct HMAC ---
  let proveMsObserved = null;
  {
    const t0 = Date.now();
    const res = await postEnvelope(validEnvelope());
    const wallMs = Date.now() - t0;
    let body = null;
    try {
      body = JSON.parse(res.raw.toString('utf8'));
    } catch {
      // stays null
    }
    const sigOk = verifyResponseSignature(res);
    const hasProof =
      body && body.proof && body.proof.pi_a && Array.isArray(body.public_signals);
    check(
      'valid envelope -> 200, APPROVE/VALID_CONDITION, proof, 13 signals, proof_tx echo',
      res.status === 200 &&
        body &&
        body.decision === 'APPROVE' &&
        body.reason_code === 'VALID_CONDITION' &&
        hasProof &&
        body.public_signals.length === 13 &&
        body.proof_tx === PROOF_TX,
      `status=${res.status} decision=${body && body.decision}/${body && body.reason_code} signals=${body && body.public_signals && body.public_signals.length} wall=${wallMs}ms`,
    );
    check('response signature verifies', sigOk);
    if (body && body.public_signals) {
      check(
        'public_signals[11] (decision) is "1"',
        body.public_signals.length === 13 && body.public_signals[11] === '1',
      );
    }
    if (hasProof) {
      const vk = JSON.parse(fs.readFileSync(VK_PATH, 'utf8'));
      const verified = await snarkjs.groth16.verify(
        vk,
        body.public_signals,
        body.proof,
      );
      check('returned proof verifies against verification_key.json', verified === true);
    }
    proveMsObserved = wallMs;
  }

  // --- 4: wrong HMAC ---
  {
    const res = await postEnvelope(validEnvelope(), { secret: 'wrongsecret' });
    check('wrong HMAC -> 401', res.status === 401, `status=${res.status}`);
  }

  // --- 5: missing signature header ---
  {
    const res = await postEnvelope(validEnvelope(), { sign: false });
    check('missing signature -> 401', res.status === 401, `status=${res.status}`);
  }

  // --- 6-10: traps, each REJECT with the right reason code + a proof ---
  const traps = [
    ['VK_SUBSTITUTION', { proof_vk: VK_OTHER }],
    ['THRESHOLD_MISMATCH', { minimum: '2500', public_balance: '1840' }],
    ['RECIPIENT_MISMATCH', { condition_recipient: OTHER_HEX }],
    ['AMOUNT_EXCEEDED', { amount: '1500' }],
    ['EXPIRED', { expiry_block: 8420000, current_block: 8420000 }],
  ];
  for (const [code, overrides] of traps) {
    const res = await postEnvelope(validEnvelope(overrides));
    const body = JSON.parse(res.raw.toString('utf8'));
    check(
      `${code} trap -> REJECT/${code} + proof`,
      res.status === 200 && body.decision === 'REJECT' && body.reason_code === code && !!body.proof,
      `status=${res.status} decision=${body.decision}/${body.reason_code} proof=${body.proof ? 'present' : 'absent'}`,
    );
  }

  // --- 11: missing fields -> REJECT/INVALID_INPUT, no proof ---
  {
    const env = validEnvelope();
    delete env.input.public_balance;
    const res = await postEnvelope(env);
    const body = JSON.parse(res.raw.toString('utf8'));
    check(
      'missing fields -> 200, REJECT/INVALID_INPUT, no proof',
      res.status === 200 && body.decision === 'REJECT' && body.reason_code === 'INVALID_INPUT' && body.proof === null,
      `status=${res.status} decision=${body.decision}/${body.reason_code}`,
    );
  }

  // --- 12: legacy flat envelope (camelCase, no input nest) still works ---
  {
    const env = {
      taskId: '1',
      vkHash: VK_HEX,
      minimum: 1000,
      publicBalance: '1460',
      expiryBlock: 8430000,
      currentBlock: '8420000',
      recipient: RECIPIENT_HEX,
      conditionRecipient: RECIPIENT_HEX,
      amount: '500',
      maxTransfer: 1000,
    };
    const res = await postEnvelope(env, { path: '/' });
    const body = JSON.parse(res.raw.toString('utf8'));
    check(
      'legacy flat envelope -> APPROVE via POST /',
      res.status === 200 && body.decision === 'APPROVE' && !!body.proof,
      `status=${res.status} decision=${body && body.decision}`,
    );
  }

  cleanup();
  const failed = results.filter((r) => !r.ok).length;
  console.log(
    `\n${results.length - failed}/${results.length} checks passed` +
      (proveMsObserved !== null ? ` (valid-case wall time incl. prove: ${proveMsObserved}ms)` : ''),
  );
  process.exit(failed === 0 ? 0 : 1);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
