# alice-charter — Charter as Code

The executable articles of the **Verum Protocol** charter (v1, 2026-08-16).
Pure Python stdlib. No dependencies. Every guarantee here is a deterministic
gate in code — models may advise, code decides.

The premise: in a persistent online world, the operator should be inside the
system that gets governed, not above it. Enforcement, administrative power,
unit economics, player records, and end-of-life continuity are written as
rules a third party can check without trusting the operator's word — or the
operator's software.

## Two-layer verification model

| Layer | Call | Proves |
|---|---|---|
| Integrity | `chain.verify()` | Nobody rewrote history. Content edits, re-hashed edits, deletions, reordering, and cross-chain replay all break verification. |
| Semantics | `ledger.audit()` | Nobody abused power *within* valid history. Reversals trace to overturned decisions, receipts to sealed price sheets, unbans to authorizations. |

The second layer is the one that normally requires legal discovery to attempt.
Here it is a function call on public data.

## Charter article → module

| Article | Module | Deterministic gates |
|---|---|---|
| I / IV — enforcement ledger | `charter/enforcement.py` | Actions must cite a reason code from a **sealed** policy. Reversals are only written by overturned decisions. Nothing is edited or deleted. `transparency_report()` computes counts + appeal overturn rate from the chain. |
| I — admin power is telemetry | `charter/admin_telemetry.py` | Item spawns, teleports, unbans, staff **data queries**, permission/config changes — all sealed, all attributed, justification mandatory. `unban` refused without a valid overturned-decision reference; `exception_report()` names any that got around the gate. |
| V — open unit economics | `charter/receipts.py` | Purchases only against a **sealed** price sheet; splits (server/development/steward/reserve) computed in integer cents by largest-remainder, summing exactly. `audit()` recomputes every receipt. |
| VI L1 — your record | `charter/player_export.py` | Per-player sealed chain; `export_player()` writes one self-contained file verifiable anywhere. |
| VI L3 — the Ark | `charter/ark.py` | End-of-life commitment (package hash + license + trigger) sealed at launch; liveness by sealed heartbeats; `evaluate()` is a pure function of public data — no discretion in the trigger. |
| — shared primitive | `charter/chain.py` | Append-only hash-linked JSONL; corrections are new links (correctable, not erasable). |
| — independent verifier | `verify_charter.py` | Standalone, zero package imports. Anyone with Python can verify a chain or an export. |

JSON Schemas for the sealed event shapes are in `schemas/`.

## How it works — diagrams

Four diagrams covering the properties that are hardest to convey in prose:
tamper detection (why re-hashing moves the break instead of hiding the edit),
correctable-not-erasable, the `verify()` / `audit()` split, and the Ark's
lapse-and-latch behaviour.

**→ [docs/DIAGRAMS.md](docs/DIAGRAMS.md)** (Mermaid, rendered inline by GitHub)
PNG versions for sharing are in [`docs/png/`](docs/png).

## Run the proofs

```
cd alice-charter
python -m unittest discover -s tests -v
```

The tests are property proofs: tamper detection (including re-hashed edits —
the break moves to the next link), correctable-not-erasable, the rogue-reversal
and bypassed-unban audits, exact split allocation across rounding, Ark
lapse/cessation triggers, and standalone export verification.

## Honest limits (read before quoting this as more than it is)

- **Hash linkage ≠ signatures.** The chain proves internal consistency. To
  prove the *operator* didn't quietly regenerate an entire chain, tip hashes
  must be anchored outside the operator's control (published, mirrored,
  countersigned). The signature layer (Ed25519, as in Verum seals) is
  pluggable and not implemented here.
- **Truncation:** a verifier holding only the file cannot detect that recent
  links were withheld. Externally published tip hashes close this.
- **Pseudonyms** are salted hashes; the salt is an operator secret. Rotating
  it breaks public linkability of history. Small-ID-space brute force is a
  known limit of any pseudonym scheme.
- **The Ark's custody is legal, not cryptographic.** Code makes the
  commitment verifiable and the trigger computable; an escrow agent /
  attorney / foundation must actually hold and release the package. The
  trigger resists a dishonest last-minute amendment by two rules:
  `evaluate()` uses the *smallest* `lapse_days` ever committed (terms can
  only tighten) and *latches* — a silence that already elapsed stays
  triggered, and the reported package/license are those in force when the
  silence began, not a weaker one swapped in afterward.
- **`audit()` catches rogue links, not rogue reality** — if the operator lies
  *into* the chain (fabricated evidence hashes), the chain faithfully records
  the lie. Evidence bundles behind `evidence_sha256` are what appeals dispute.
