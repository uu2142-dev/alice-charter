"""Article I / IV -- the public enforcement ledger.

The inversion of the Ashes ban lists (character names, no account IDs, no
timestamps, no appeal outcomes, crisis-timed dumps). Here the whole chain
is public from genesis; subjects are pseudonymous; and the write paths are
deterministic gates:

  * Every action must cite a reason code from a SEALED policy version --
    you cannot ban for a reason you never published.
  * Appeals reference actions; decisions reference appeals; a reversal is
    only ever written by an overturned decision. There is no other write
    path for `enforcement.reversal` in this API.
  * Nothing is edited or deleted. A reversal is a new link; the original
    action stays in the chain (correctable, not erasable).
  * transparency_report() computes counts and the appeal overturn rate --
    the number the industry ceiling (Xbox, 26 percent in 2025) publishes
    only as a PDF statistic -- straight from the verifiable chain.
  * audit() re-checks the SEMANTICS of the whole chain: every reversal
    must trace to an overturned decision, every decision to a real appeal,
    every appeal to a real action, every action to a sealed policy. This
    catches rogue links appended around the API (imported history, insider
    with file access) -- verify() alone would call those links "valid."
"""
from __future__ import annotations

import hashlib
import re

from .chain import Chain, ChainError, canonical, sha256_hex

ACTIONS = ("warn", "suspend", "ban", "item_removal", "economy_rollback")
APPEAL_OUTCOMES = ("upheld", "overturned")

_SHA256_RE = re.compile(r"[0-9a-f]{64}")


def pseudonym(salt: str, account_id: str) -> str:
    """Stable pseudonym: sha256(salt:account)[:16].

    The salt stays private with the operator; the pseudonym is stable so
    patterns (repeat offenders, appeal histories) stay queryable in public
    without exposing identity. Rotating the salt breaks linkability with
    all prior history -- do not rotate casually.
    """
    if not salt:
        raise ValueError("empty salt")
    if not account_id:
        raise ValueError("empty account_id")
    return hashlib.sha256(f"{salt}:{account_id}".encode("utf-8")).hexdigest()[:16]


class EnforcementLedger:
    def __init__(self, chain: Chain):
        self.chain = chain

    # -- policy --------------------------------------------------------

    def publish_policy(self, version: str, reason_codes: dict) -> dict:
        """Seal an enforcement policy: the set of reason codes actions may cite."""
        if not version:
            raise ValueError("policy version required")
        if not reason_codes:
            raise ValueError("policy must define at least one reason code")
        codes = {str(k): str(v) for k, v in sorted(reason_codes.items())}
        body = {
            "version": version,
            "reason_codes": codes,
            "policy_sha256": sha256_hex(canonical(codes)),
        }
        return self.chain.append("enforcement.policy", body)

    def current_policy(self) -> dict | None:
        for link in reversed(self.chain.links()):
            if link["kind"] == "enforcement.policy":
                return link
        return None

    # -- actions -------------------------------------------------------

    def action(
        self,
        subject: str,
        action: str,
        reason_code: str,
        evidence_sha256: str,
        actor_role: str,
        actor_id: str,
        note: str = "",
        occurred_at: str | None = None,
    ) -> dict:
        if action not in ACTIONS:
            raise ValueError(f"unknown action {action!r}; must be one of {ACTIONS}")
        policy = self.current_policy()
        if policy is None:
            raise ChainError("no sealed enforcement policy; call publish_policy() first")
        if reason_code not in policy["body"]["reason_codes"]:
            raise ValueError(
                f"reason code {reason_code!r} is not in sealed policy "
                f"{policy['body']['version']} -- publish the policy change first"
            )
        if not _SHA256_RE.fullmatch(evidence_sha256 or ""):
            raise ValueError("evidence_sha256 must be a sha256 hex digest of the evidence bundle")
        if not subject:
            raise ValueError("subject pseudonym required")
        body = {
            "subject": subject,
            "action": action,
            "reason_code": reason_code,
            "policy_version": policy["body"]["version"],
            "policy_seq": policy["seq"],
            "evidence_sha256": evidence_sha256,
            "actor_role": actor_role,
            "actor_id": actor_id,
            "note": note,
        }
        return self.chain.append("enforcement.action", body, occurred_at=occurred_at)

    # -- appeals -------------------------------------------------------

    def appeal(self, subject: str, action_seq: int, statement: str = "") -> dict:
        act = self.chain.get(action_seq)
        if act is None or act["kind"] != "enforcement.action":
            raise ChainError(f"seq {action_seq} is not an enforcement action")
        if act["body"]["subject"] != subject:
            raise ChainError("appeal subject does not match action subject")
        body = {
            "subject": subject,
            "action_seq": action_seq,
            "action_hash": act["hash"],
            "statement": statement,
        }
        return self.chain.append("enforcement.appeal", body)

    def decide(self, appeal_seq: int, outcome: str, reviewer_id: str, rationale: str) -> dict:
        """Decide an appeal. An overturned decision automatically seals the
        reversal link -- the ONLY write path for `enforcement.reversal`."""
        if outcome not in APPEAL_OUTCOMES:
            raise ValueError(f"outcome must be one of {APPEAL_OUTCOMES}")
        if not (rationale or "").strip():
            raise ValueError("a decision requires a written rationale")
        ap = self.chain.get(appeal_seq)
        if ap is None or ap["kind"] != "enforcement.appeal":
            raise ChainError(f"seq {appeal_seq} is not an appeal")
        for link in self.chain.links():
            if (
                link["kind"] == "enforcement.decision"
                and link["body"].get("appeal_seq") == appeal_seq
            ):
                raise ChainError(f"appeal {appeal_seq} already decided at seq {link['seq']}")
        body = {
            "appeal_seq": appeal_seq,
            "appeal_hash": ap["hash"],
            "action_seq": ap["body"]["action_seq"],
            "outcome": outcome,
            "reviewer_id": reviewer_id,
            "rationale": rationale,
        }
        decision = self.chain.append("enforcement.decision", body)
        if outcome == "overturned":
            act = self.chain.get(ap["body"]["action_seq"])
            self.chain.append(
                "enforcement.reversal",
                {
                    "action_seq": act["seq"],
                    "action_hash": act["hash"],
                    "decision_seq": decision["seq"],
                    "decision_hash": decision["hash"],
                    "subject": act["body"]["subject"],
                },
            )
        return decision

    # -- transparency --------------------------------------------------

    def transparency_report(self) -> dict:
        actions = appeals = decisions = overturned = reversals = 0
        by_action: dict = {}
        for link in self.chain.links():
            kind = link["kind"]
            if kind == "enforcement.action":
                actions += 1
                a = link["body"]["action"]
                by_action[a] = by_action.get(a, 0) + 1
            elif kind == "enforcement.appeal":
                appeals += 1
            elif kind == "enforcement.decision":
                decisions += 1
                if link["body"]["outcome"] == "overturned":
                    overturned += 1
            elif kind == "enforcement.reversal":
                reversals += 1
        return {
            "actions": actions,
            "by_action": by_action,
            "appeals": appeals,
            "decisions": decisions,
            "overturned": overturned,
            "overturn_rate": round(overturned / decisions, 4) if decisions else None,
            "reversals": reversals,
            "chain_valid": self.chain.verify()["valid"],
        }

    # -- semantic audit ------------------------------------------------

    def audit(self) -> list[dict]:
        """Re-check chain SEMANTICS, not just hashes. Returns violations.

        Catches links that were appended around this API (rogue writes with
        file access, imported history): reversals without an overturned
        decision, decisions without a real appeal, appeals without a real
        action, actions citing an unsealed policy or reason code.
        """
        links = self.chain.links()
        by_seq = {l["seq"]: l for l in links}
        violations: list[dict] = []
        decided: set = set()  # appeal seqs already resolved by a valid decision

        def flag(link, reason):
            violations.append({"seq": link["seq"], "kind": link["kind"], "reason": reason})

        # policies sealed at or before a given seq
        for link in links:
            kind, body = link["kind"], link.get("body", {})
            if kind == "enforcement.action":
                pol = by_seq.get(body.get("policy_seq"))
                if (
                    pol is None
                    or pol["kind"] != "enforcement.policy"
                    or pol["seq"] > link["seq"]
                    or pol["body"].get("version") != body.get("policy_version")
                    or body.get("reason_code") not in pol["body"].get("reason_codes", {})
                ):
                    flag(link, "action does not trace to a sealed policy reason code")
            elif kind == "enforcement.appeal":
                act = by_seq.get(body.get("action_seq"))
                if (
                    act is None
                    or act["kind"] != "enforcement.action"
                    or act["hash"] != body.get("action_hash")
                    or act["body"].get("subject") != body.get("subject")
                ):
                    flag(link, "appeal does not trace to a matching action")
            elif kind == "enforcement.decision":
                ap = by_seq.get(body.get("appeal_seq"))
                if (
                    ap is None
                    or ap["kind"] != "enforcement.appeal"
                    or ap["hash"] != body.get("appeal_hash")
                ):
                    flag(link, "decision does not trace to a real appeal")
                elif ap["body"].get("action_seq") != body.get("action_seq"):
                    flag(link, "decision action_seq does not match the appeal it cites")
                elif body.get("appeal_seq") in decided:
                    flag(link, "appeal already resolved by an earlier decision")
                else:
                    decided.add(body.get("appeal_seq"))
            elif kind == "enforcement.reversal":
                dec = by_seq.get(body.get("decision_seq"))
                act = by_seq.get(body.get("action_seq"))
                if (
                    dec is None
                    or dec["kind"] != "enforcement.decision"
                    or dec["hash"] != body.get("decision_hash")
                    or dec["body"].get("outcome") != "overturned"
                    or dec["body"].get("action_seq") != body.get("action_seq")
                ):
                    flag(link, "reversal does not trace to an overturned decision")
                elif act is None or act["hash"] != body.get("action_hash"):
                    flag(link, "reversal does not trace to the original action")
        return violations
