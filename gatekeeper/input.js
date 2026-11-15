'use strict';
// Shared input handling for the zkVerify Agent Games Proof Gatekeeper endpoint.
//
// Schema per https://agentgames.zkverify.io/build (read 2026-11-15):
// task envelope { type: "agent-games.proof-gatekeeper.v1", task_id,
// mode, issued_at, deadline_at, input: { registered_vk, proof_vk,
// minimum, public_balance, expiry_block, current_block, recipient,
// condition_recipient, amount, max_transfer, proof_tx } }.
// Preflight: { type: "agent-games.preflight.v1", agent_id, issued_at,
// nonce } -> respond { ok: true, protocolVersion: "v1" }.
// Extraction stays defensive (aliases + nests) in case the live envelope
// differs slightly from the doc; values may be hex strings, decimal
// strings, or JSON numbers.
//
// Fail-closed throughout: anything missing or unparseable -> REJECT.

const path = require('path');
const crypto = require('crypto');

// BN254 (bn128) scalar-field prime. The 256-bit vk hash exceeds it, so
// snarkjs reduces hash inputs mod p; comparisons must do the same.
const BN128_PRIME =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;

// Registered gatekeeper vk hash, from
// https://agentgames.zkverify.io/api/circuit-info (network: mainnet).
const REGISTERED_VK_HASH_HEX =
  '0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0';
const REGISTERED_VK_HASH_DEC =
  '48612629870452471351995307734854562318858385272285416761371572079729769805744';
const REGISTERED_VK_HASH_MODP = (
  BigInt(REGISTERED_VK_HASH_DEC) % BN128_PRIME
).toString();

const WASM_PATH = path.join(__dirname, '..', 'circuits', 'gatekeeper.wasm');
const ZKEY_PATH = path.join(__dirname, '..', 'circuits', 'gatekeeper_final.zkey');
const VK_PATH = path.join(__dirname, '..', 'circuits', 'verification_key.json');

// ---------------------------------------------------------------------------
// Value normalization
// ---------------------------------------------------------------------------

// Parse a value that may be a hex string ("0x..."), a decimal string, or a
// JSON number into a BigInt. Returns null when unparseable or negative.
function toBigInt(value) {
  if (typeof value === 'bigint') return value < 0n ? null : value;
  if (typeof value === 'number') {
    if (!Number.isInteger(value) || value < 0) return null;
    return BigInt(value);
  }
  if (typeof value === 'string') {
    const s = value.trim();
    if (/^0x[0-9a-fA-F]+$/.test(s)) {
      try {
        return BigInt(s);
      } catch {
        return null;
      }
    }
    if (/^[0-9]+$/.test(s)) {
      try {
        return BigInt(s);
      } catch {
        return null;
      }
    }
    return null;
  }
  return null;
}

// Decimal-string form of a value, or null when unparseable.
function toDecimalString(value) {
  const b = toBigInt(value);
  return b === null ? null : b.toString(10);
}

// mod-p reduced decimal string of a hash value, or null when unparseable.
function hashModP(value) {
  const b = toBigInt(value);
  return b === null ? null : (b % BN128_PRIME).toString(10);
}

// Random 64-bit salt (private circuit input), fresh per task.
function randomSalt() {
  return BigInt('0x' + crypto.randomBytes(8).toString('hex')).toString(10);
}

// Map a task id to a circuit field element. Real task ids are strings
// like "gk_8d31_..." — not numbers. Numeric ids pass through; anything
// else is SHA-256 hashed (Node has no keccak256 built in) and reduced
// mod p. Deterministic per task id. If practice shows the platform
// expects a different mapping (e.g. keccak), change this one function.
function taskIdToField(taskId) {
  if (taskId === undefined || taskId === null) return '0';
  const asNum = toBigInt(taskId);
  if (asNum !== null) return (asNum % BN128_PRIME).toString(10);
  const hash = crypto
    .createHash('sha256')
    .update(String(taskId), 'utf8')
    .digest('hex');
  return (BigInt('0x' + hash) % BN128_PRIME).toString(10);
}

// ---------------------------------------------------------------------------
// Envelope extraction
// ---------------------------------------------------------------------------

// Field name aliases, in preference order. First scope (below) holding any
// alias with a non-null value wins.
const FIELD_ALIASES = {
  minimum: ['minimum', 'minBalance', 'min_balance', 'min'],
  publicBalance: ['publicBalance', 'public_balance', 'balance'],
  amount: ['amount', 'transferAmount', 'transfer_amount'],
  maxTransfer: ['maxTransfer', 'max_transfer', 'maxAmount', 'max_amount'],
  recipient: ['recipient', 'to', 'destination'],
  conditionRecipient: [
    'conditionRecipient',
    'condition_recipient',
    'expectedRecipient',
    'expected_recipient',
  ],
  expiryBlock: ['expiryBlock', 'expiry_block', 'expiry', 'expirationBlock'],
  currentBlock: ['currentBlock', 'current_block', 'blockNumber', 'block_number'],
  taskId: ['taskId', 'task_id', 'id'],
  // The real envelope carries TWO vk hashes: registered_vk (the key the
  // condition was registered under) and proof_vk (the key the transfer's
  // proof was made with). Approve only when they match. A lone vkHash /
  // vk / vk_hash is treated as the proof vk (compared against the known
  // registered constant).
  registeredVk: [
    'registered_vk',
    'registeredVk',
    'registeredVkHash',
    'registered_vk_hash',
    'registeredKeyHash',
  ],
  proofVk: [
    'proof_vk',
    'proofVk',
    'proofVkHash',
    'proof_vk_hash',
    'vkHash',
    'vk_hash',
    'verificationKeyHash',
    'vk',
  ],
  proofTx: ['proof_tx', 'proofTx'],
};

// Candidate scopes, in search order: top level, then one level of common
// nests, then two levels for the most likely nest combos.
function candidateScopes(envelope) {
  const scopes = [envelope];
  // The documented envelope nests all condition fields under `input`.
  const nests = ['input', 'task', 'condition', 'data', 'payload', 'publicInputs', 'inputs'];
  const first = [];
  for (const n of nests) {
    const v = envelope && typeof envelope === 'object' ? envelope[n] : undefined;
    if (v && typeof v === 'object') {
      scopes.push(v);
      first.push(v);
    }
  }
  for (const parent of first) {
    for (const n of nests) {
      const v = parent[n];
      if (v && typeof v === 'object') scopes.push(v);
    }
  }
  return scopes;
}

function extractFields(envelope) {
  const scopes = candidateScopes(envelope);
  const fields = {};
  for (const [field, aliases] of Object.entries(FIELD_ALIASES)) {
    for (const scope of scopes) {
      let found = false;
      for (const alias of aliases) {
        if (
          scope &&
          typeof scope === 'object' &&
          scope[alias] !== undefined &&
          scope[alias] !== null
        ) {
          fields[field] = scope[alias];
          found = true;
          break;
        }
      }
      if (found) break;
    }
  }
  return fields;
}

// ---------------------------------------------------------------------------
// Decision
// ---------------------------------------------------------------------------

// Approve (1) ONLY if every check holds. Any missing/unparseable field, any
// failed check -> reject (0). Returns { decision, reasonCode, reasons[] }.
// Reason codes: VALID_CONDITION + the documented trap codes
// (VK_SUBSTITUTION, THRESHOLD_MISMATCH, RECIPIENT_MISMATCH) + AMOUNT_EXCEEDED,
// EXPIRED, INVALID_INPUT for the remaining failure modes.
function decide(fields) {
  const reasons = [];
  const fail = (reasonCode, why) => {
    reasons.push(why);
    return { decision: 0, reasonCode, reasons };
  };

  const minimum = toBigInt(fields.minimum);
  const publicBalance = toBigInt(fields.publicBalance);
  const amount = toBigInt(fields.amount);
  const maxTransfer = toBigInt(fields.maxTransfer);
  const recipient = toBigInt(fields.recipient);
  const conditionRecipient = toBigInt(fields.conditionRecipient);
  const expiryBlock = toBigInt(fields.expiryBlock);
  const currentBlock = toBigInt(fields.currentBlock);

  const required = {
    minimum,
    publicBalance,
    amount,
    maxTransfer,
    recipient,
    conditionRecipient,
    expiryBlock,
    currentBlock,
  };
  for (const [name, parsed] of Object.entries(required)) {
    if (parsed === null)
      return fail('INVALID_INPUT', `missing/unparseable field: ${name}`);
  }

  // vk check: proof_vk must equal registered_vk (mod-p reduced, because
  // the 256-bit hashes exceed the field prime). When the envelope carries
  // only proof_vk, compare against the known registered constant. When
  // it carries neither, the check is skipped (legacy envelopes).
  const proofVk = fields.proofVk;
  if (proofVk !== undefined && proofVk !== null) {
    const proofModP = hashModP(proofVk);
    if (proofModP === null) return fail('INVALID_INPUT', 'unparseable proof_vk');
    let registeredModP = REGISTERED_VK_HASH_MODP;
    const registeredVk = fields.registeredVk;
    if (registeredVk !== undefined && registeredVk !== null) {
      registeredModP = hashModP(registeredVk);
      if (registeredModP === null)
        return fail('INVALID_INPUT', 'unparseable registered_vk');
    }
    if (proofModP !== registeredModP)
      return fail('VK_SUBSTITUTION', 'proof_vk != registered_vk');
  }

  if (publicBalance < minimum)
    return fail('THRESHOLD_MISMATCH', 'publicBalance < minimum');
  if (recipient !== conditionRecipient)
    return fail('RECIPIENT_MISMATCH', 'recipient != conditionRecipient');
  if (amount > maxTransfer)
    return fail('AMOUNT_EXCEEDED', 'amount > maxTransfer');
  if (expiryBlock <= currentBlock)
    return fail('EXPIRED', 'expiryBlock <= currentBlock');

  return { decision: 1, reasonCode: 'VALID_CONDITION', reasons };
}

// ---------------------------------------------------------------------------
// Circuit input construction
// ---------------------------------------------------------------------------

// Build the 13-signal circuit input for a given decision. Returns
// { input } on success or { error } when a required numeric input is
// missing/unparseable (then no proof can be produced at all).
function buildCircuitInput(fields, decision) {
  const minimum = toDecimalString(fields.minimum);
  const publicBalance = toDecimalString(fields.publicBalance);
  const amount = toDecimalString(fields.amount);
  const maxTransfer = toDecimalString(fields.maxTransfer);
  const recipient = toDecimalString(fields.recipient);
  const conditionRecipient = toDecimalString(fields.conditionRecipient);
  const expiryBlock = toDecimalString(fields.expiryBlock);
  const currentBlock = toDecimalString(fields.currentBlock);
  // taskId maps to a field element (string ids are hashed); never missing.
  const taskId = taskIdToField(fields.taskId);

  const missing = [];
  if (minimum === null) missing.push('minimum');
  if (publicBalance === null) missing.push('publicBalance');
  if (amount === null) missing.push('amount');
  if (maxTransfer === null) missing.push('maxTransfer');
  if (recipient === null) missing.push('recipient');
  if (conditionRecipient === null) missing.push('conditionRecipient');
  if (expiryBlock === null) missing.push('expiryBlock');
  if (currentBlock === null) missing.push('currentBlock');
  if (missing.length > 0) {
    return { error: `cannot build circuit input, missing/unparseable: ${missing.join(', ')}` };
  }

  // registeredVkHash: the envelope's registered_vk when present (the
  // condition's own key), else the known tournament constant.
  // proofVkHash: the envelope's proof_vk when present — even if it
  // mismatches the registered one (the proof then attests the real inputs
  // with decision 0; if the circuit refuses, proving fails and we answer
  // decision 0 without a proof). Otherwise the registered hash.
  let registeredVkHash = REGISTERED_VK_HASH_DEC;
  if (fields.registeredVk !== undefined && fields.registeredVk !== null) {
    registeredVkHash = toDecimalString(fields.registeredVk);
    if (registeredVkHash === null) {
      return { error: 'cannot build circuit input, unparseable registered_vk' };
    }
  }
  let proofVkHash = registeredVkHash;
  if (fields.proofVk !== undefined && fields.proofVk !== null) {
    proofVkHash = toDecimalString(fields.proofVk);
    if (proofVkHash === null) {
      return { error: 'cannot build circuit input, unparseable proof_vk' };
    }
  }

  return {
    input: {
      registeredVkHash,
      proofVkHash,
      minimum,
      publicBalance,
      expiryBlock,
      currentBlock,
      recipient,
      conditionRecipient,
      amount,
      maxTransfer,
      decision: String(decision),
      taskId,
      salt: randomSalt(),
    },
  };
}

// Direct circuit input (prove.js): validate a raw 13-signal object.
const CIRCUIT_SIGNALS = [
  'registeredVkHash',
  'proofVkHash',
  'minimum',
  'publicBalance',
  'expiryBlock',
  'currentBlock',
  'recipient',
  'conditionRecipient',
  'amount',
  'maxTransfer',
  'decision',
  'taskId',
  'salt',
];

function isDirectCircuitInput(obj) {
  return (
    obj &&
    typeof obj === 'object' &&
    CIRCUIT_SIGNALS.every((k) => obj[k] !== undefined && obj[k] !== null)
  );
}

function normalizeDirectInput(obj) {
  const input = {};
  for (const k of CIRCUIT_SIGNALS) {
    const d = toDecimalString(obj[k]);
    if (d === null) return { error: `unparseable circuit signal: ${k}` };
    input[k] = d;
  }
  return { input };
}

// Short, safe prefix for logging hashes/signatures (never log full values).
function shortHash(value) {
  if (value === undefined || value === null) return null;
  const s = String(value);
  return s.length > 8 ? s.slice(0, 8) + '…' : s;
}

module.exports = {
  BN128_PRIME,
  REGISTERED_VK_HASH_HEX,
  REGISTERED_VK_HASH_DEC,
  REGISTERED_VK_HASH_MODP,
  WASM_PATH,
  ZKEY_PATH,
  VK_PATH,
  CIRCUIT_SIGNALS,
  toBigInt,
  toDecimalString,
  hashModP,
  randomSalt,
  taskIdToField,
  extractFields,
  decide,
  buildCircuitInput,
  isDirectCircuitInput,
  normalizeDirectInput,
  shortHash,
};
