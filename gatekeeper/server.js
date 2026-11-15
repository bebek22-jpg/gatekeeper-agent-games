'use strict';
// zkVerify Agent Games — Proof Gatekeeper agent endpoint.
//
// Node.js, no framework (built-in http only).
//
// Flow per task:
//   1. Read the raw request body.
//   2. Verify HMAC-SHA256 (header x-agent-games-signature) over the RAW body
//      BEFORE parsing. Mismatch/missing -> 401, no further processing.
//   3. Extract condition fields defensively, decide approve (1) / reject (0).
//   4. Generate a Groth16 proof locally with snarkjs + the tournament
//      circuit (decision 0 is also proven when the inputs allow it).
//   5. Respond { decision, proof, publicSignals, taskId }, signed with the
//      same HMAC secret over the raw response body.
//
// Fail closed everywhere: any doubt -> decision 0, no proof, never crash,
// never hang (45s internal guard; platform deadline is 60s).
//
// Env:
//   PORT              listen port (default 3101)
//   HMAC_SECRET       platform-issued HMAC secret
//   HMAC_SECRET_FILE  path to a file holding the secret (wins over HMAC_SECRET)
//
// One of HMAC_SECRET / HMAC_SECRET_FILE is required at startup.

const http = require('http');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

let snarkjs;
try {
  snarkjs = require('snarkjs'); // gatekeeper/node_modules after npm install
} catch {
  snarkjs = require('../node_modules/snarkjs');
}

const {
  WASM_PATH,
  ZKEY_PATH,
  extractFields,
  decide,
  buildCircuitInput,
  shortHash,
} = require('./input');

const PORT = parseInt(process.env.PORT || '3101', 10);
const MAX_BODY_BYTES = 1024 * 1024; // 1 MB — task envelopes are small
const INTERNAL_TIMEOUT_MS = 45_000; // platform hard deadline is 60s
const LOG_PATH = path.join(__dirname, 'endpoint.log');
const LOG_MAX_BYTES = 5 * 1024 * 1024;

// ---------------------------------------------------------------------------
// Secret loading (startup only; never logged)
// ---------------------------------------------------------------------------

function loadSecret() {
  if (process.env.HMAC_SECRET_FILE) {
    const raw = fs.readFileSync(process.env.HMAC_SECRET_FILE, 'utf8');
    const secret = raw.trim();
    if (!secret) throw new Error('HMAC_SECRET_FILE is empty');
    return secret;
  }
  if (process.env.HMAC_SECRET) {
    const secret = process.env.HMAC_SECRET.trim();
    if (!secret) throw new Error('HMAC_SECRET is empty');
    return secret;
  }
  throw new Error('set HMAC_SECRET or HMAC_SECRET_FILE');
}

let HMAC_SECRET;
try {
  HMAC_SECRET = loadSecret();
} catch (err) {
  console.error(`[gatekeeper] FATAL: ${err.message}`);
  process.exit(1);
}

// ---------------------------------------------------------------------------
// Logging (JSON lines; rotate >5MB to endpoint.log.1). Never logs the secret
// or full signature/hash values.
// ---------------------------------------------------------------------------

function rotateLogIfNeeded() {
  try {
    const st = fs.statSync(LOG_PATH);
    if (st.size > LOG_MAX_BYTES) {
      fs.renameSync(LOG_PATH, LOG_PATH + '.1');
    }
  } catch {
    // No log file yet, or rotation failed — append will surface real errors.
  }
}

function log(entry) {
  try {
    rotateLogIfNeeded();
    fs.appendFileSync(
      LOG_PATH,
      JSON.stringify({ ts: new Date().toISOString(), ...entry }) + '\n',
    );
  } catch (err) {
    console.error('[gatekeeper] log write failed:', err.message);
  }
}

// ---------------------------------------------------------------------------
// HMAC helpers
// ---------------------------------------------------------------------------

function hmacHex(bodyBuffer) {
  return crypto
    .createHmac('sha256', HMAC_SECRET)
    .update(bodyBuffer)
    .digest('hex');
}

// Accept bare hex or "sha256=" prefixed. Constant-time compare; length
// mismatch is a fail (timingSafeEqual throws on unequal lengths).
function verifySignature(rawBody, headerValue) {
  if (!headerValue || typeof headerValue !== 'string') return false;
  let sig = headerValue.trim().toLowerCase();
  if (sig.startsWith('sha256=')) sig = sig.slice('sha256='.length);
  if (!/^[0-9a-f]{64}$/.test(sig)) return false;
  const expected = Buffer.from(hmacHex(rawBody), 'hex');
  const actual = Buffer.from(sig, 'hex');
  if (expected.length !== actual.length) return false;
  return crypto.timingSafeEqual(expected, actual);
}

// ---------------------------------------------------------------------------
// Response helper — always signs the raw response body.
// ---------------------------------------------------------------------------

function sendJson(res, status, payload) {
  const body = JSON.stringify(payload);
  const bodyBuf = Buffer.from(body, 'utf8');
  res.writeHead(status, {
    'Content-Type': 'application/json',
    'x-agent-games-signature': hmacHex(bodyBuf),
  });
  res.end(bodyBuf);
}

// ---------------------------------------------------------------------------
// Task handler
// ---------------------------------------------------------------------------

async function handleTask(req, res, rawBody) {
  const startedAt = Date.now();
  let responded = false;
  let taskIdEcho = null;

  // 45s internal guard: force a decision-0 response if proving (or anything
  // else) is still stuck. Proving normally takes ~1.5s.
  const guard = setTimeout(() => {
    if (responded) return;
    responded = true;
    log({
      event: 'TIMEOUT_GUARD',
      taskId: taskIdEcho,
      responseMs: Date.now() - startedAt,
    });
    sendJson(res, 200, {
      decision: 0,
      proof: null,
      publicSignals: null,
      taskId: taskIdEcho,
      error: 'internal timeout: decision 0 (fail closed)',
    });
  }, INTERNAL_TIMEOUT_MS);

  const finish = (status, payload, logExtra) => {
    if (responded) return;
    responded = true;
    clearTimeout(guard);
    log({
      event: 'TASK',
      taskId: taskIdEcho,
      responseMs: Date.now() - startedAt,
      ...logExtra,
    });
    sendJson(res, status, payload);
  };

  try {
    // --- 1. HMAC verification on the RAW body, before parsing. ---
    const sigHeader = req.headers['x-agent-games-signature'];
    if (!verifySignature(rawBody, sigHeader)) {
      log({
        event: 'HMAC_FAIL',
        taskId: null,
        sigPrefix: shortHash(sigHeader),
        responseMs: Date.now() - startedAt,
      });
      clearTimeout(guard);
      responded = true;
      sendJson(res, 401, { error: 'invalid signature' });
      return;
    }

    // --- 2. Parse defensively. ---
    let envelope;
    try {
      envelope = JSON.parse(rawBody.toString('utf8'));
    } catch (err) {
      finish(400, {
        decision: 0,
        proof: null,
        publicSignals: null,
        taskId: null,
        error: 'invalid JSON envelope',
      }, { hmac: 'ok', decision: 0, error: 'PARSE_FAIL' });
      return;
    }
    if (!envelope || typeof envelope !== 'object' || Array.isArray(envelope)) {
      finish(400, {
        decision: 0,
        proof: null,
        publicSignals: null,
        taskId: null,
        error: 'envelope must be a JSON object',
      }, { hmac: 'ok', decision: 0, error: 'ENVELOPE_NOT_OBJECT' });
      return;
    }

    // --- 3. Extract + decide. ---
    const fields = extractFields(envelope);
    // Echo taskId exactly as received (string/number as-is).
    taskIdEcho =
      fields.taskId !== undefined && fields.taskId !== null
        ? fields.taskId
        : null;
    const { decision, reasons } = decide(fields);

    // --- 4. Build circuit input; prove when possible. ---
    const built = buildCircuitInput(fields, decision);
    if (built.error) {
      finish(200, {
        decision: 0,
        proof: null,
        publicSignals: null,
        taskId: taskIdEcho,
        error: built.error,
      }, {
        hmac: 'ok',
        decision: 0,
        proof: false,
        reasons,
        error: 'INPUT_BUILD_FAIL',
      });
      return;
    }

    const proveStarted = Date.now();
    let proofResult;
    try {
      proofResult = await snarkjs.groth16.fullProve(
        built.input,
        WASM_PATH,
        ZKEY_PATH,
      );
    } catch (err) {
      const reason = String(err && err.message ? err.message : err).slice(0, 300);
      finish(200, {
        decision: 0,
        proof: null,
        publicSignals: null,
        taskId: taskIdEcho,
        error: `proving failed: ${reason}`,
      }, {
        hmac: 'ok',
        decision: 0,
        proof: false,
        reasons,
        proveMs: Date.now() - proveStarted,
        error: 'PROVE_FAIL',
      });
      return;
    }
    const proveMs = Date.now() - proveStarted;

    finish(200, {
      decision,
      proof: proofResult.proof,
      publicSignals: proofResult.publicSignals.map(String),
      taskId: taskIdEcho,
    }, {
      hmac: 'ok',
      decision,
      proof: true,
      proveMs,
      reasons: decision === 0 ? reasons : undefined,
      vkPrefix: shortHash(fields.vkHash),
    });
  } catch (err) {
    // Last-resort catch: never crash, never hang.
    const reason = String(err && err.message ? err.message : err).slice(0, 300);
    finish(200, {
      decision: 0,
      proof: null,
      publicSignals: null,
      taskId: taskIdEcho,
      error: `internal error: ${reason}`,
    }, { hmac: 'ok', decision: 0, proof: false, error: 'INTERNAL_ERROR' });
  }
}

// ---------------------------------------------------------------------------
// HTTP server
// ---------------------------------------------------------------------------

const server = http.createServer((req, res) => {
  // Health: no auth.
  if (req.method === 'GET' && req.url === '/health') {
    sendJson(res, 200, { ok: true });
    return;
  }

  if (req.method === 'POST' && (req.url === '/' || req.url === '/task')) {
    const chunks = [];
    let size = 0;
    let aborted = false;
    req.on('data', (chunk) => {
      size += chunk.length;
      if (size > MAX_BODY_BYTES) {
        aborted = true;
        sendJson(res, 413, { error: 'body too large' });
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => {
      if (aborted) return;
      handleTask(req, res, Buffer.concat(chunks)).catch((err) => {
        console.error('[gatekeeper] handler error:', err);
        if (!res.writableEnded) {
          sendJson(res, 200, {
            decision: 0,
            proof: null,
            publicSignals: null,
            taskId: null,
            error: 'internal error',
          });
        }
      });
    });
    req.on('error', () => {
      if (!res.writableEnded) {
        sendJson(res, 400, { error: 'request error' });
      }
    });
    return;
  }

  sendJson(res, 404, { error: 'not found' });
});

// Keep the whole request/response cycle inside the 60s platform deadline.
server.requestTimeout = 55_000;
server.headersTimeout = 10_000;

process.on('uncaughtException', (err) => {
  console.error('[gatekeeper] uncaughtException:', err);
  log({ event: 'UNCAUGHT', error: String(err && err.message ? err.message : err).slice(0, 300) });
});
process.on('unhandledRejection', (err) => {
  console.error('[gatekeeper] unhandledRejection:', err);
});

server.listen(PORT, () => {
  console.log(`[gatekeeper] listening on port ${PORT} (POST / or /task, GET /health)`);
});
