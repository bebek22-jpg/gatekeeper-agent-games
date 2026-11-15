# Proof Gatekeeper — zkVerify Agent Games agent endpoint

Node.js (no framework, built-in `http` only). Receives the platform's signed
JSON task envelope, verifies the HMAC, decides approve/reject, generates a
Groth16 proof locally with snarkjs + the tournament circuit, and responds —
all within the platform's 60s hard deadline. Fail closed on any doubt.

## Files

| file | purpose |
|---|---|
| `server.js` | HTTP endpoint (the agent). |
| `input.js` | Shared: envelope extraction, decision rules, circuit-input builder, constants. |
| `prove.js` | Standalone proving CLI (testing / debugging). |
| `test_local.js` | Local end-to-end test suite (spawns the server, dummy secret). |
| `endpoint.log` | JSON-lines request log (rotates >5MB to `endpoint.log.1`). |
| `node_modules` | Symlink to `../node_modules` (snarkjs 0.7.6, reused — no install). |

Circuit artifacts live in `../circuits/` (`gatekeeper.wasm`,
`gatekeeper_final.zkey`, `verification_key.json`).

## Environment variables

| var | required | notes |
|---|---|---|
| `PORT` | no | Listen port, default `3101`. |
| `HMAC_SECRET` | yes* | Platform-issued HMAC secret (from the dashboard's "Rotate Secret"). |
| `HMAC_SECRET_FILE` | yes* | Path to a file holding the secret. **Wins over `HMAC_SECRET` if both set.** Preferred in production (keeps the secret out of the process env). |

\* One of the two secret sources is required — the server exits at startup
without one. The secret is never logged.

No other env vars are needed. Outbound network is not used at runtime
(proving is fully local); the egress-proxy vars (`NODE_USE_ENV_PROXY`,
`NODE_EXTRA_CA_CERTS`, `SSL_CERT_FILE`) are only relevant for npm/install
steps, not for running the server.

## How to run

```sh
cd ~/workspace/zkverify-agent-games/gatekeeper

# with a secret file (preferred)
printf '%s' '<platform-secret>' > /path/to/hmac_secret   # 0600, outside the repo
PORT=3101 HMAC_SECRET_FILE=/path/to/hmac_secret node server.js

# or with the env var
PORT=3101 HMAC_SECRET='<platform-secret>' node server.js
```

Health check (no auth): `GET /health` → `{"ok":true}`

The endpoint must be reachable at a **public HTTPS** URL for the platform —
put it behind a reverse proxy / tunnel that terminates TLS (hosting is the
coordinator's job, not this server's; the server itself speaks plain HTTP on
localhost).

## Request / response

**Incoming** — `POST /` or `POST /task`, JSON body, header
`x-agent-games-signature`: HMAC-SHA256 hex of the raw request body with the
platform secret (bare hex or `sha256=`-prefixed). Verified against the raw
bytes **before** parsing; mismatch or missing header → `401`, nothing else
happens.

**Outgoing** — JSON, signed the same way (`x-agent-games-signature` header
over the raw response body). Schema per
https://agentgames.zkverify.io/build:

```json
{
  "decision": "APPROVE",
  "reason_code": "VALID_CONDITION",
  "proof": { "pi_a": ["...", "...", "1"], "pi_b": [[...]], "pi_c": ["...", "...", "1"], "protocol": "groth16", "curve": "bn128" },
  "public_signals": ["<commitment>", "<registeredVk mod p>", "<proofVk mod p>", "1000", "1460", "8430000", "8420000", "<recipient>", "<conditionRecipient>", "500", "1000", "1", "<taskId field>"],
  "proof_tx": "0xa8...2c"
}
```

- `decision`: `"APPROVE"` or `"REJECT"` (strings).
- `reason_code`: `VALID_CONDITION` on approve; on reject one of
  `VK_SUBSTITUTION`, `THRESHOLD_MISMATCH`, `RECIPIENT_MISMATCH`,
  `AMOUNT_EXCEEDED`, `EXPIRED`, `INVALID_INPUT` (plus `TIMEOUT` /
  `PROVE_FAILED` for internal failures).
- `proof`: the snarkjs proof object, or `null` when no proof could be
  produced (an omitted proof costs −2; a decision-0 proof is produced
  whenever the numeric inputs allow it).
- `public_signals`: 13 decimal strings, or `null` with no proof. Order:
  commitment, registered vk hash (mod-p reduced), proof vk hash (mod-p
  reduced), minimum, publicBalance, expiryBlock, currentBlock, recipient,
  conditionRecipient, amount, maxTransfer, decision (0/1), taskId field.
  The salt is private (never in signals).
- `proof_tx`: echoes the task's `proof_tx` when present (optional
  on-chain audit pointer); omitted otherwise.

**Preflight** — the platform sends a signed
`{"type": "agent-games.preflight.v1", "agent_id": "agt_...", "issued_at":
"...", "nonce": "..."}` before any task. The endpoint must answer
`{"ok": true, "protocolVersion": "v1"}` (signed, HTTP 200, within 10s).
Preflight must pass before the platform marks the agent active. Detected
by the `type` field after HMAC verification; no proving involved.

## Envelope fields expected

Real schema (per /build), with the condition fields nested under `input`:

```json
{
  "type": "agent-games.proof-gatekeeper.v1",
  "task_id": "gk_8d31_...",
  "mode": "competition",
  "issued_at": "<issued-at>",
  "deadline_at": "<deadline-at>",
  "input": {
    "registered_vk": "0x7d...91",
    "proof_vk": "0x13...aa",
    "minimum": "1000",
    "public_balance": "1460",
    "expiry_block": 8430000,
    "current_block": 8420000,
    "recipient": "0xDe42...9f01",
    "condition_recipient": "0xDe42...9f01",
    "amount": "500",
    "max_transfer": "1000",
    "proof_tx": "0xa8...2c"
  }
}
```

Extraction stays defensive (see `input.js`): each field is searched at the
top level and under the nests `input`, `task`, `condition`, `data`,
`payload`, `publicInputs`, `inputs` (plus two-level combos), under several
alias spellings, and values may be hex strings (`0x…`), decimal strings,
or JSON numbers. A legacy flat camelCase envelope still works.

| field | meaning | aliases searched |
|---|---|---|
| `minimum` | minimum required balance | `minBalance`, `min_balance`, `min` |
| `public_balance` | public balance to check | `publicBalance`, `balance` |
| `amount` | transfer amount | `transferAmount`, `transfer_amount` |
| `max_transfer` | max allowed transfer | `maxTransfer`, `maxAmount`, `max_amount` |
| `recipient` | transfer recipient (address) | `to`, `destination` |
| `condition_recipient` | expected recipient | `conditionRecipient`, `expectedRecipient`, `expected_recipient` |
| `expiry_block` | condition expiry block | `expiryBlock`, `expiry`, `expirationBlock` |
| `current_block` | current block | `currentBlock`, `blockNumber`, `block_number` |
| `task_id` | task identifier (string like `gk_...`; hashed to a field element — see below) | `taskId`, `id` |
| `registered_vk` | vk the condition was registered under | `registeredVk`, `registeredVkHash`, `registered_vk_hash` |
| `proof_vk` | vk the transfer's proof was made with | `proofVk`, `proofVkHash`, `proof_vk_hash`, `vkHash`, `vk_hash`, `vk` |
| `proof_tx` | on-chain audit pointer (echoed back) | `proofTx` |

**taskId mapping**: real task ids are non-numeric strings, but the circuit
needs a field element. `taskIdToField()` passes numeric ids through and
maps anything else via SHA-256 mod p (Node has no keccak256 built in).
Deterministic per task id. If the platform ever rejects proofs over the
taskId signal, this one function is where the mapping changes.

## Decision rules (fail closed)

Approve (`"APPROVE"`, reason `VALID_CONDITION`) **only** if ALL hold:

1. `proof_vk == registered_vk` — compared **mod the BN254 field prime**,
   because the 256-bit hashes exceed the prime and snarkjs reduces them
   (same reduction the circuit applies). When the envelope carries only
   `proof_vk`, it is compared against the known registered gatekeeper hash
   `0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0`.
   Mismatch → `VK_SUBSTITUTION`.
2. `public_balance >= minimum`, else `THRESHOLD_MISMATCH`
3. `recipient == condition_recipient` (compared as integers, so hex vs
   decimal spellings match), else `RECIPIENT_MISMATCH`
4. `amount <= max_transfer`, else `AMOUNT_EXCEEDED`
5. `expiry_block > current_block`, else `EXPIRED`

Any missing/unparseable field → `"REJECT"` with `INVALID_INPUT`. A
decision-0 proof is still produced when all numeric inputs are present
(the circuit accepts decision 0 with mismatched inputs — verified in
tests); if proving fails, the response is `"REJECT"` with `PROVE_FAILED`
and `proof: null`.

## Timing / safety rails

- Proving: ~1.1s cold (first prove in a fresh process), ~0.4s warm.
- 45s internal guard forces a REJECT response if anything stalls;
  server `requestTimeout` is 55s (platform deadline is 60s).
- Request body cap 1MB (`413` above).
- Logs: JSON lines in `endpoint.log`, rotated at 5MB. Logs taskId,
  hmac ok/fail, decision, reasonCode, prove/response ms, and only the
  first 8 chars of any hash/signature. **Never logs the secret or full
  signature values.**

## Standalone proving

```sh
# raw 13-signal circuit input (e.g. ../input_valid.json)
node prove.js ../input_valid.json --verify

# or a task envelope — extracts, decides, proves with the same rules
node prove.js envelope.json
```

Prints `{ decision, proof, publicSignals, taskId, proveMs }` (+ `verified`
with `--verify`). Exit 1 on any failure. (prove.js still uses the numeric
0/1 decision and camelCase keys internally — the server maps to the
platform's string/snake_case response shape.)

Note: snarkjs leaves worker threads alive after proving, so `prove.js`
calls `process.exit(0)` explicitly after printing. The workers are reused
across proves (thread count stays flat) — no leak in the long-lived server.

## Tests

```sh
node test_local.js   # 15 checks, localhost only, dummy secret, port 3102
```

Covers: health; preflight handshake; valid real-schema envelope →
APPROVE/VALID_CONDITION + proof that verifies against the vk + proof_tx
echo; response-signature verification; wrong/missing HMAC → 401; all five
trap types → REJECT with the right reason code + decision-0 proof; missing
fields → REJECT/INVALID_INPUT without proof; legacy flat envelope still
works.

## Open questions (for practice mode to settle)

1. **taskId mapping** — the platform may or may not check the taskId
   public signal against the task id. Currently SHA-256 mod p. If practice
   rejects proofs, try keccak256 (needs a vendored impl or a Python
   subprocess — pycryptodome is available) or a plain numeric mapping.
2. **Kurier / proof_tx** — the response proof is the scored evidence;
   `proof_tx` is documented as an optional audit pointer, so Kurier
   submission is currently NOT done. If practice shows a proof reference
   is required for scoring, add a Kurier submit step after proving
   (Kurier key via env, same secret-file pattern as the HMAC secret) —
   that needs lapet's email for the Kurier account.
