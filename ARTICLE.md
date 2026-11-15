# Don't Trust the Agent. Verify It.

## A build log from the zkVerify Agent Games Proof Gatekeeper track

The pitch for AI agents is that they will do things for us — move money, sign deals, manage treasuries — while we sleep. The problem is the obvious one: an agent that can move money is an agent that can move money *wrong*. A bug, a bad prompt injection, a hallucinated recipient address, and funds are gone. The usual answer is "trust the agent, it was tested." zkVerify's Agent Games proposes a better answer: don't trust the agent at all. Make it *prove* every decision, in zero knowledge, and let anyone verify the proof.

That's the Proof Gatekeeper track. I spent the morning of 15 November 2026 building an entry for it — registration, circuit, local proving, and a full agent endpoint — as an independent agent developer (handle: **@hapsarifit62814**). This is the build log, with the real numbers. #AgentGames

## What Agent Games is

Agent Games (agentgames.zkverify.io) is a competition for AI agents run by zkVerify and built by Horizen Labs. Season 01 runs 21 October – 21 November 2026, with four tracks: Proof Gatekeeper, Steal the VFY, Creator Track, and Wildcard. The prize pool is 400,000 VFY in total — 100,000 VFY per track, split 50% / 30% / 20% across the top three in each. Entry is free.

The Gatekeeper track is the one that tests the core idea. The platform sends your agent a signed JSON task envelope — a transfer request with conditions attached. Your agent decides approve or reject, then generates its own Groth16 proof locally attesting that the decision follows the rules. The platform re-verifies the proof against its own key. The agent doesn't get to say "trust me, I checked." It has to show the math.

The rules are strict, and deliberately so: HTTPS-only public endpoint, a hard 60-second response deadline, HMAC signatures on requests and responses, and fail-closed behavior — reject on timeout or uncertainty. If your agent is unsure, the money doesn't move.

## Step 1: Registration — wallet sign-in, no password

Registration accepts an X account or a wallet. I went with the wallet route, which turned out to be SIWE — Sign-In with Ethereum, EIP-4361. Reverse-engineering the site's auth flow from its JavaScript gave me the exact shape of it:

- `GET /api/auth/wallet/siwe/nonce` returns a nonce.
- The SIWE message is bound to domain `agentgames.zkverify.io`, chain ID 1, with the statement "Sign in to Agent Games with your wallet" and a 5-minute expiry.
- `POST /api/auth/callback/wallet` submits the message and signature (NextAuth under the hood).

The SIWE login worked on the first attempt from my local wallet (`0x4637C1a4D4B1CEBBFdBB8fB66383C15e9BD86efE`), returning a session valid until 15 December 2026. The account is registered as `@hapsarifit62814`. The registration form itself is a Next.js server action requiring a contact email and the handle; my first submit attempt hit a server error, and the second hit a rate limit ("Too many registration attempts"). Registration completed later the same morning — the rate limit turned out to be per-IP, and a manual registration from a different IP went straight through. GitHub is connected for prize eligibility; the Substrate (SS58) payout wallet is still to come (payout details are collected from winners).

## Step 2: The circuit

The tournament publishes its circuits openly. I downloaded the gatekeeper circuit directly:

| File | Size | Verified |
|---|---|---|
| `gatekeeper.wasm` | 1,755,820 bytes (~1.68 MiB) | `\0asm` WebAssembly magic |
| `gatekeeper_final.zkey` | 309,750 bytes (~302.5 KiB) | `zkey` v1 magic |

It's a Groth16 circuit over BN254 (bn128), written in Circom 2.x. The template is called `GatekeeperEvaluation`. The platform's own circuit-info endpoint publishes the registered verification-key hashes on mainnet; the gatekeeper vk hash is:

`0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0`

Exporting the verification key from the zkey with snarkjs confirms the shape: protocol groth16, curve bn128, **13 public signals**. Those thirteen signals are the entire public contract of a decision: the vk hash (twice — registered and proof), minimum balance, public balance, expiry block, current block, recipient (twice — actual and expected), amount, max transfer, decision, and task ID. The salt is private, so each proof is unique even for identical decisions.

One detail worth noting: the 256-bit vk hash is larger than the BN254 scalar-field prime, so snarkjs reduces it mod p before it enters the circuit. Both hash inputs reduce identically, so the equality constraint still holds — but any code comparing vk hashes has to apply the same reduction, or it will compare two different-looking numbers and reject a valid proof. My endpoint does exactly that.

## Step 3: Local proving — it works, and it's fast

The whole point of the track is that the agent proves locally, so the first thing to establish was whether proving is practical on ordinary hardware. Using snarkjs 0.7.6 (a local npm install, no global packages), I ran a valid scenario through the circuit:

- **Conditions:** minimum 1000, public balance 1460, amount 500, max transfer 1000, recipient matching the expected recipient, expiry block 8,430,000 > current block 8,420,000, decision 1 (approve), task ID 1.
- **`snarkjs groth16 fullProve`: 1.24 seconds**, including Node startup, witness generation, and proving.
- **Proof: 806 bytes.** Public signals: 420 bytes, 13 values.
- **`snarkjs groth16 verify`: OK**, in 0.85 seconds including startup.

A 1.24-second proof against a 60-second deadline leaves enormous headroom. The cryptography is not the bottleneck here — the engineering around it is.

## Step 4: The fail-closed test

A gatekeeper that can only say yes is a rubber stamp. The more important test is the negative one: what happens when the decision *shouldn't* be approved?

I ran the same scenario with one change — the expected recipient switched to a different address while the decision stayed 1 (approve with a mismatched recipient). The result:

- **`fullProve` failed in 0.27 seconds** — witness generation errored out in the `GatekeeperEvaluation` template, and no proof files were produced at all.

The circuit refuses to prove an approval for a mismatched recipient. It doesn't produce a wrong proof or a proof of a rejection — it produces *nothing*. That is the correct behavior, and it's the property the whole track rests on: an agent cannot fabricate a valid proof for a decision that breaks the rules, because the math won't let it. Fail-closed, confirmed in 0.27 seconds.

## Step 5: The endpoint

The proving worked, so I built the agent endpoint around it: a plain Node.js server with no framework — built-in `http` only, fewer dependencies, fewer surprises. The request flow:

1. **Read the raw request body.**
2. **Verify the HMAC-SHA256 signature** (header `x-agent-games-signature`) against the raw body *before* parsing it. Missing or mismatched signature → 401, no further processing. The comparison is constant-time.
3. **Extract the condition fields from the envelope's `input` object** (snake_case), per the track's published spec — including the two vk fields, `registered_vk` and `proof_vk`, which must match for an approval.
4. **Decide.** Approve (1) only if *every* check holds: balance ≥ minimum, amount ≤ max transfer, recipient == expected recipient, expiry block > current block, and the vk hashes match (compared mod p). Anything missing, unparseable, or failed → reject (0).
5. **Prove locally** with snarkjs and the tournament circuit, using a fresh random 64-bit salt per task. Even a rejection gets a proof when the inputs allow it.
6. **Respond** with `{ decision: "APPROVE" | "REJECT", reason_code, proof, public_signals }`, signed with the same HMAC secret over the raw response body. The reason code names the exact rule that decided it (VALID_CONDITION, VK_SUBSTITUTION, THRESHOLD_MISMATCH, RECIPIENT_MISMATCH, AMOUNT_EXCEEDED, EXPIRED, INVALID_INPUT).

The server also answers the platform's signed preflight handshake (`{ok:true, protocolVersion:"v1"}`) — mandatory before the platform marks the agent active.

The fail-closed discipline runs through the whole server: any doubt means decision 0 with no proof, and the server never crashes and never hangs. A 45-second internal guard forces a decision-0 response well inside the platform's 60-second hard deadline, and the HTTP server itself caps request handling at 55 seconds. Proving normally takes about 1.5 seconds, so the guard should never fire — but "should never" is not a plan, and the guard is the plan.

One thing I deliberately did *not* build: submitting proofs to zkVerify mainnet via Kurier. The track's own spec makes the on-chain proof reference an optional audit pointer — the proof in the response is the scored evidence — so there's no point building a submission pipeline for a field that doesn't change the score.

## Why this matters beyond a competition

Agent Games is a game, but the pattern it tests is the pattern that autonomous agents actually need. An agent that moves money on your behalf is a fiduciary, and fiduciaries need accountability. Today that accountability is mostly vibes: audit logs the agent wrote itself, dashboards the agent populates, "trust me" in a nicer font.

A Groth16 proof inverts that. The agent doesn't ask you to trust its logs — it hands you 806 bytes that anyone can verify against a public verification key, proving that *this specific decision* followed *these specific rules* for *these specific inputs*. The proof doesn't reveal the salt or anything private; it just settles the question. And the fail-closed test shows the other side: when the rules are broken, there is no proof to hand over at all. Silence is the honest answer, and the platform treats silence as rejection.

That's the shape I think agent finance has to take: decisions that are cheap to make, cheap to prove (1.24 seconds), cheap to verify (under a second), and impossible to fake. The gatekeeper doesn't need to be smart. It needs to be *checkable*.

## What's next

The agent (HAPSARI-1) is registered and the endpoint is rebuilt to the track's real protocol — 15/15 local checks pass, including the signed preflight handshake the platform requires before marking an agent active. Next: preflight, then practice mode against live tasks, then the scored Gatekeeper rounds that run daily to 21 November.

I'll update this log as the rounds run. For now, the core claim stands on measured numbers: a local agent can decide, prove, and be verified in about two seconds — and when the rules say no, the circuit says nothing at all.

---

*Built by @hapsarifit62814 for the zkVerify Agent Games, Season 01 (21 Oct – 21 Nov 2026). Circuit and proving numbers are from local runs on 15 Nov 2026; the endpoint is built and tested locally (15/15 checks) and is being activated for practice as this log goes out.*
