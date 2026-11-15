'use strict';
// Shared input handling for the zkVerify Agent Games Proof Gatekeeper endpoint.
//
// The platform's exact task-envelope schema is unknown until practice mode
// reveals it, so extraction is deliberately flexible: fields are searched at
// the top level and under common nests, and values may be hex strings,
// decimal strings, or JSON numbers.
//
// Fail-closed throughout: anything missing or unparseable -> decision 0.

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
  vkHash: [
    'vkHash',
    'vk_hash',
    'registeredVkHash',
    'proofVkHash',
    'verificationKeyHash',
    'vk',
  ],
};

// Candidate scopes, in search order: top level, then one level of common
// nests, then two levels for the most likely nest combos.
function candidateScopes(envelope) {
  const scopes = [envelope];
  const nests = ['task', 'condition', 'data', 'payload', 'publicInputs', 'inputs'];
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
// failed check -> reject (0). Returns { decision, reasons[] }.
function decide(fields) {
  const reasons = [];
  const fail = (why) => {
    reasons.push(why);
    return { decision: 0, reasons };
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
    if (parsed === null) return fail(`missing/unparseable field: ${name}`);
  }

  if (publicBalance < minimum)
    return fail('publicBalance < minimum');
  if (amount > maxTransfer) return fail('amount > maxTransfer');
  if (recipient !== conditionRecipient)
    return fail('recipient != conditionRecipient');
  if (expiryBlock <= currentBlock)
    return fail('expiryBlock <= currentBlock');

  // vk hash check, only when the envelope carries one. Compare mod-p
  // reduced decimals because the 256-bit hash exceeds the field prime.
  if (fields.vkHash !== undefined && fields.vkHash !== null) {
    const got = hashModP(fields.vkHash);
    if (got === null) return fail('unparseable vkHash');
    if (got !== REGISTERED_VK_HASH_MODP)
      return fail('vkHash != registered vk hash');
  }

  return { decision: 1, reasons };
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
  const taskId = toDecimalString(fields.taskId);

  const missing = [];
  if (minimum === null) missing.push('minimum');
  if (publicBalance === null) missing.push('publicBalance');
  if (amount === null) missing.push('amount');
  if (maxTransfer === null) missing.push('maxTransfer');
  if (recipient === null) missing.push('recipient');
  if (conditionRecipient === null) missing.push('conditionRecipient');
  if (expiryBlock === null) missing.push('expiryBlock');
  if (currentBlock === null) missing.push('currentBlock');
  if (taskId === null) missing.push('taskId');
  if (missing.length > 0) {
    return { error: `cannot build circuit input, missing/unparseable: ${missing.join(', ')}` };
  }

  // proofVkHash: the envelope's vk hash when present (even if it mismatches
  // the registered one — the proof then attests the real inputs with
  // decision 0; if the circuit refuses, proving fails and we answer
  // decision 0 without a proof). Otherwise the registered hash.
  const proofVkHash =
    fields.vkHash !== undefined && fields.vkHash !== null
      ? toDecimalString(fields.vkHash)
      : REGISTERED_VK_HASH_DEC;
  if (proofVkHash === null) {
    return { error: 'cannot build circuit input, unparseable vkHash' };
  }

  return {
    input: {
      registeredVkHash: REGISTERED_VK_HASH_DEC,
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
  extractFields,
  decide,
  buildCircuitInput,
  isDirectCircuitInput,
  normalizeDirectInput,
  shortHash,
};
