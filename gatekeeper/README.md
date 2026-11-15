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
| `node_modules` | Created by `npm install` (snarkjs 0.7.6). |

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
over the raw response body):

```json
{
  "decision": 1,
  "proof": { "pi_a": ["...", "...", "1"], "pi_b": [[...]], "pi_c": ["...", "...", "1"], "protocol": "groth16", "curve": "bn128" },
  "publicSignals": ["<commitment>", "<vkHash mod p>", "<vkHash mod p>", "1000", "1460", "8430000", "8420000", "<recipient>", "<conditionRecipient>", "500", "1000", "1", "1"],
  "taskId": "1"
}
```

- `decision`: number `0` (reject) or `1` (approve).
- `proof`: the snarkjs proof object, or `null` when no proof could be
  produced (then an `error` string field explains why).
- `publicSignals`: 13 decimal strings, or `null` with no proof. Order:
  commitment, vk hash (mod-p reduced, ×2), minimum, publicBalance,
  expiryBlock, currentBlock, recipient, conditionRecipient, amount,
  maxTransfer, decision, taskId. The salt is private (never in signals).
- `taskId`: echoed exactly as received (string or number as-is).

## Envelope fields expected

The exact platform schema is unknown until practice mode reveals it, so
extraction is defensive (see `input.js`): each field is searched at the top
level and under the nests `task`, `condition`, `data`, `payload`,
`publicInputs`, `inputs` (plus two-level combos like `task.condition`),
under several alias spellings, and values may be hex strings (`0x…`),
decimal strings, or JSON numbers.

| field | meaning | aliases searched |
|---|---|---|
| `minimum` | minimum required balance | `minBalance`, `min` |
| `publicBalance` | public balance to check | `balance` |
| `amount` | transfer amount | `transferAmount` |
| `maxTransfer` | max allowed transfer | `maxAmount` |
| `recipient` | transfer recipient (address) | `to`, `destination` |
| `conditionRecipient` | expected recipient | `expectedRecipient` |
| `expiryBlock` | condition expiry block | `expiry`, `expirationBlock` |
| `currentBlock` | current block | `blockNumber` |
| `taskId` | task identifier (echoed; must be numeric to prove) | `id` |
| `vkHash` | verification-key hash to check (optional) | `registeredVkHash`, `proofVkHash`, `verificationKeyHash`, `vk` |

## Decision rules (fail closed)

Approve (`decision: 1`) **only** if ALL hold:

1. `publicBalance >= minimum`
2. `amount <= maxTransfer`
3. `recipient == conditionRecipient` (compared as integers, so hex vs decimal spellings match)
4. `expiryBlock > currentBlock`
5. if a vk hash is present in the envelope, it equals the registered
   gatekeeper hash `0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0`
   — compared **mod the BN254 field prime**, because the 256-bit hash
   exceeds the prime and snarkjs reduces it (same reduction the circuit
   applies).

Any missing/unparseable field → `decision: 0`. A decision-0 proof is still
produced when all numeric inputs are present (the circuit accepts decision 0
with mismatched recipients / wrong vk hash — verified in tests); if proving
fails, the response is `decision: 0` with `proof: null` and an `error` note.

## Timing / safety rails

- Proving: ~1.1s cold (first prove in a fresh process), ~0.4s warm.
- 45s internal guard forces a decision-0 response if anything stalls;
  server `requestTimeout` is 55s (platform deadline is 60s).
- Request body cap 1MB (`413` above).
- Logs: JSON lines in `endpoint.log`, rotated at 5MB. Logs taskId,
  hmac ok/fail, decision, prove/response ms, and only the first 8 chars of
  any hash/signature. **Never logs the secret or full signature values.**

## Standalone proving

```sh
# raw 13-signal circuit input (e.g. ../input_valid.json)
node prove.js ../input_valid.json --verify

# or a task envelope — extracts, decides, proves with the same rules
node prove.js envelope.json
```

Prints `{ decision, proof, publicSignals, taskId, proveMs }` (+ `verified`
with `--verify`). Exit 1 on any failure.

Note: snarkjs leaves worker threads alive after proving, so `prove.js`
calls `process.exit(0)` explicitly after printing. The workers are reused
across proves (thread count stays flat) — no leak in the long-lived server.

## Tests

```sh
node test_local.js   # 12 checks, localhost only, dummy secret
```

Covers: valid envelope → decision 1 + proof that verifies against the vk;
response-signature verification; wrong/missing HMAC → 401; recipient
mismatch → decision 0 (with decision-0 proof); nested envelope; missing
fields → decision 0 without proof; wrong vk hash → decision 0; health.

## What to adjust once practice mode reveals the real schema

1. **Envelope shape** — if fields live under a nest or alias not covered,
   add the nest to `candidateScopes()` / the alias to `FIELD_ALIASES` in
   `input.js`, then re-run `test_local.js` with a real captured envelope.
2. **Response shape** — if the platform wants extra fields (e.g.
   `circuitVersion`, `proofReference`, Kurier job id) or different key
   spellings, add them in `server.js`'s `finish(...)` calls. Keep the
   primary shape (`decision`, `proof`, `publicSignals`, `taskId`) intact.
3. **Proof submission** — the current endpoint returns the proof to the
   platform for it to verify. If practice shows the agent must instead
   submit the proof to Kurier/zkVerify itself and return a `proofReference`,
   that submission step belongs in `handleTask` after proving (Kurier key
   via env, same secret-file pattern as the HMAC secret).
4. **taskId format** — if taskIds are non-numeric (UUIDs etc.), the circuit
   input can't carry them; the current code then answers decision 0 without
   a proof. If that happens, decide with the coordinator whether to hash
   the taskId into a field element or to echo it only.
