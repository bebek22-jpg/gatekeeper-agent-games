'use strict';
// Local end-to-end test for server.js. No extra deps; localhost only.
//
// Spawns the server with a DUMMY secret, then runs:
//   1. valid envelope + correct HMAC  -> 200, decision 1, proof present,
//      response signature verifies, proof verifies against the vk
//   2. valid envelope + wrong HMAC    -> 401
//   3. valid envelope + no signature  -> 401
//   4. recipient-mismatch envelope    -> 200, decision 0
//   5. nested envelope (task/condition nests) -> 200, decision 1
//   6. envelope with missing fields   -> 200, decision 0, no proof
//   7. GET /health                    -> {"ok":true}
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

const PORT = 3101;
const SECRET = 'testsecret123';
const BASE = `http://127.0.0.1:${PORT}`;

const VK_HEX = '0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0';
const RECIPIENT_HEX = '0x1111111111111111111111111111111111111111';
const RECIPIENT_DEC = '97433442488726861213578988847752201310395502865';
const OTHER_HEX = '0x2222222222222222222222222222222222222222';

// Valid scenario, derived from ../input_valid.json, with MIXED formats to
// exercise normalization (numbers, decimal strings, hex strings).
function validEnvelope() {
  return {
    taskId: '1',
    vkHash: VK_HEX,
    minimum: 1000,
    publicBalance: '1460',
    expiryBlock: 8430000,
    currentBlock: '8420000',
    recipient: RECIPIENT_HEX,
    conditionRecipient: RECIPIENT_DEC,
    amount: '500',
    maxTransfer: 1000,
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

  // --- Case 7 first (cheap): health ---
  {
    const res = await request({ method: 'GET', path: '/health' });
    const body = JSON.parse(res.raw.toString('utf8'));
    check('GET /health returns {"ok":true}', res.status === 200 && body.ok === true);
  }

  // --- Case 1: valid envelope, correct HMAC ---
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
      body && body.proof && body.proof.pi_a && Array.isArray(body.publicSignals);
    check(
      'valid envelope -> 200, decision 1, proof present',
      res.status === 200 && body && body.decision === 1 && hasProof,
      `status=${res.status} decision=${body && body.decision} signals=${body && body.publicSignals && body.publicSignals.length} wall=${wallMs}ms`,
    );
    check('response signature verifies', sigOk);
    check('taskId echoed', body && String(body.taskId) === '1');
    if (body && body.publicSignals) {
      check(
        'publicSignals has 13 entries, decision=1, taskId=1',
        body.publicSignals.length === 13 &&
          body.publicSignals[11] === '1' &&
          body.publicSignals[12] === '1',
      );
    }
    // Verify the returned proof against the verification key.
    if (hasProof) {
      const vk = JSON.parse(fs.readFileSync(VK_PATH, 'utf8'));
      const verified = await snarkjs.groth16.verify(
        vk,
        body.publicSignals,
        body.proof,
      );
      check('returned proof verifies against verification_key.json', verified === true);
    }
    proveMsObserved = wallMs;
  }

  // --- Case 2: wrong HMAC ---
  {
    const res = await postEnvelope(validEnvelope(), { secret: 'wrongsecret' });
    check('wrong HMAC -> 401', res.status === 401, `status=${res.status}`);
  }

  // --- Case 3: missing signature header ---
  {
    const res = await postEnvelope(validEnvelope(), { sign: false });
    check('missing signature -> 401', res.status === 401, `status=${res.status}`);
  }

  // --- Case 4: recipient mismatch -> decision 0 ---
  {
    const env = validEnvelope();
    env.conditionRecipient = OTHER_HEX;
    const res = await postEnvelope(env);
    const body = JSON.parse(res.raw.toString('utf8'));
    check(
      'recipient mismatch -> 200, decision 0',
      res.status === 200 && body.decision === 0,
      `status=${res.status} decision=${body.decision} proof=${body.proof ? 'present' : 'absent'}`,
    );
  }

  // --- Case 5: nested envelope -> decision 1 ---
  {
    const env = {
      taskId: '42',
      task: {
        condition: {
          minimum: '1000',
          publicBalance: 1460,
          amount: 500,
          maxTransfer: '1000',
          recipient: RECIPIENT_HEX,
          conditionRecipient: RECIPIENT_HEX,
          expiryBlock: '8430000',
          currentBlock: 8420000,
        },
      },
      data: { vkHash: VK_HEX },
    };
    const res = await postEnvelope(env, { path: '/' });
    const body = JSON.parse(res.raw.toString('utf8'));
    check(
      'nested envelope (task.condition + data.vkHash) -> decision 1 via POST /',
      res.status === 200 && body.decision === 1 && !!body.proof,
      `status=${res.status} decision=${body && body.decision} taskId=${body && body.taskId}`,
    );
  }

  // --- Case 6: missing fields -> decision 0, no proof ---
  {
    const env = { taskId: '7', minimum: 1000 }; // everything else missing
    const res = await postEnvelope(env);
    const body = JSON.parse(res.raw.toString('utf8'));
    check(
      'missing fields -> 200, decision 0, no proof',
      res.status === 200 && body.decision === 0 && body.proof === null,
      `status=${res.status} decision=${body.decision} error=${body.error || ''}`,
    );
  }

  // --- Case 8 (extra): vk hash mismatch -> decision 0 ---
  {
    const env = validEnvelope();
    env.vkHash = '0x6c56509f1c56fd1fd4e9737f906d2220f4b95f1d507f1adf6899085bd74be047'; // vfyPolicy vk, not gatekeeper
    const res = await postEnvelope(env);
    const body = JSON.parse(res.raw.toString('utf8'));
    check(
      'wrong vk hash -> decision 0',
      res.status === 200 && body.decision === 0,
      `status=${res.status} decision=${body.decision} proof=${body.proof ? 'present' : 'absent'}`,
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
