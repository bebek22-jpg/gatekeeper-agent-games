# Gatekeeper — a verifiable agent for zkVerify Agent Games

An autonomous agent that acts as a **Proof Gatekeeper** for payment
requests: it receives a signed task envelope describing a transfer, decides
approve/reject against the stated conditions, and proves its decision with
a Groth16 zero-knowledge proof — so the platform never has to trust the
agent's word, only the proof.

Built for [zkVerify Agent Games](https://agentgames.zkverify.io) Season 01
(Proof Gatekeeper track) by **bebek22**.

## Why this exists

Autonomous agents that move money are only useful if their decisions are
checkable. The Gatekeeper pattern makes every decision verifiable: the
agent can't approve a transfer that breaks the rules, because the circuit
itself refuses to prove a rule-breaking approval (tested: an approve with
a mismatched recipient fails witness generation in 0.27s — the proof
simply doesn't exist).

## How it works

```
platform ──POST signed envelope──▶ endpoint (server.js)
                                      │
                    1. verify HMAC-SHA256 on the RAW body
                       (before parsing anything; 401 on failure)
                                      │
                    2. decide — approve ONLY if ALL hold:
                         • publicBalance ≥ minimum
                         • amount ≤ maxTransfer
                         • recipient == conditionRecipient
                         • expiryBlock > currentBlock
                         • vk hash matches the registered vk (mod p)
                       anything missing/unparseable → reject (fail closed)
                                      │
                    3. prove locally with snarkjs + the tournament
                       circuit (Groth16, BN254) — ~0.6s warm, ~1.2s cold
                                      │
                    4. respond {decision, proof, publicSignals, taskId}
                       signed with the same HMAC, well inside the 60s deadline
```

Rejects still carry a proof when all numeric inputs are present — only
genuinely missing inputs produce a proof-less decision-0 response.

## Layout

| path | what |
|---|---|
| `gatekeeper/` | The agent: `server.js` (endpoint), `input.js` (envelope extraction + decision rules + circuit-input builder), `prove.js` (standalone proving CLI), `test_local.js` (12-check local suite), `package.json` |
| `circuits/` | Tournament artifacts: `gatekeeper.wasm`, `gatekeeper_final.zkey`, `verification_key.json` (Groth16/bn128, 13 public signals) |
| `examples/` | A real valid input + its proof and public signals (806-byte proof, verified OK) |
| `render.yaml` | Free-tier deploy blueprint (Render) |

## Run it

```bash
cd gatekeeper
npm install
HMAC_SECRET=<platform-issued secret> PORT=3101 node server.js
```

`GET /health` → `{"ok":true}`. `POST /task` (or `/`) with header
`x-agent-games-signature: <HMAC-SHA256 hex of the raw body>`.

```bash
node test_local.js   # 12 local end-to-end checks, dummy secret
node prove.js examples/input_valid.json --verify
```

## Key decisions

- **Fail closed, always.** Any doubt — missing field, bad HMAC, unparseable
  number, vk mismatch — means reject. An agent that moves money must
  default to "no".
- **HMAC before parsing.** The signature is verified on the raw body
  before any JSON parsing, so malformed or tampered envelopes never reach
  the decision logic.
- **Defensive envelope extraction.** Real envelopes nest and alias fields;
  the extractor searches two levels deep across `task`/`condition`/`data`/
  `payload`/`publicInputs`/`inputs` and accepts hex, decimal, or number
  spellings.
- **Mod-p vk comparison.** The 256-bit vk hash exceeds the BN254 field
  prime, so snarkjs reduces it mod p — comparisons do the same.
- **No framework.** Built-in `http` only; one dependency (snarkjs).
- **No secrets in the repo.** The HMAC secret comes from the environment
  or a file (`HMAC_SECRET_FILE`), never from code or config.

## Measured performance

| case | result |
|---|---|
| Valid proof (cold process) | 1.24s, 806 bytes, `groth16 verify` OK |
| Valid proof (warm server) | ~0.6s |
| Invalid approve (rule-breaking) | witness fails in 0.27s — no proof produced |
| End-to-end POST → signed response | ~1.5s over a public tunnel |

## License

MIT. The circuit artifacts are the tournament's, used here for the
competition entry.
