"""Article I -- admin power is telemetry.

Every operator capability that could confer advantage or rewrite outcomes
is itself a sealed public event: item spawns, teleports, unbans, staff
data queries, permission and config changes, world edits.

Two mechanisms, deliberately redundant:

  * The GATE: log() refuses an `unban` that does not carry a valid
    authorization reference to an overturned enforcement decision.
    Staff justification is mandatory on every event.
  * The AUDIT: exception_report() re-scans the chain and flags any unban
    whose authorization does not resolve -- catching imported history,
    writes that bypassed this API, or tampering.

  "Who overrode enforcement?" -- the question the Ashes investigation
  needed federal discovery to even ask -- is exception_report() here.
"""
from __future__ import annotations

from .chain import Chain, ChainError
from .enforcement import EnforcementLedger

EVENTS = (
    "item_spawn",
    "teleport",
    "unban",
    "data_query",
    "permission_change",
    "config_change",
    "world_edit",
)


class AdminLedger:
    def __init__(self, chain: Chain, enforcement: EnforcementLedger | None = None):
        self.chain = chain
        self.enforcement = enforcement

    def log(
        self,
        event: str,
        staff_id: str,
        justification: str,
        target: str | None = None,
        params: dict | None = None,
        authorization: dict | None = None,
        occurred_at: str | None = None,
    ) -> dict:
        if event not in EVENTS:
            raise ValueError(f"unknown admin event {event!r}; must be one of {EVENTS}")
        if not staff_id:
            raise ValueError("staff_id is required -- admin actions are attributed, not anonymous")
        if not (justification or "").strip():
            raise ValueError("justification is required for every admin event")
        if event == "unban":
            ok, reason = self._resolve_authorization(authorization, target)
            if not ok:
                raise ChainError(f"unban refused: {reason}")
        body = {
            "event": event,
            "staff_id": staff_id,
            "justification": justification,
            "target": target,
            "params": params or {},
        }
        if authorization is not None:
            body["authorization"] = authorization
        return self.chain.append("admin.event", body, occurred_at=occurred_at)

    # -- authorization -------------------------------------------------

    def _resolve_authorization(self, authorization, target) -> tuple[bool, str]:
        """An unban is only authorized by an overturned enforcement decision,
        referenced by seq AND hash on the enforcement chain, AND concerning
        the very player being unbanned. Without the last check, one genuine
        overturn would launder unbans for arbitrary unrelated players."""
        if not isinstance(authorization, dict):
            return False, "missing authorization (requires an overturned enforcement decision)"
        if self.enforcement is None:
            return False, "no enforcement ledger wired to this admin ledger"
        seq = authorization.get("decision_seq")
        want_hash = authorization.get("decision_hash")
        link = self.enforcement.chain.get(seq) if isinstance(seq, int) else None
        if link is None:
            return False, f"decision seq {seq!r} not found on enforcement chain"
        if link["hash"] != want_hash:
            return False, "decision hash mismatch (reference does not match sealed link)"
        if link["kind"] != "enforcement.decision":
            return False, "referenced link is not an enforcement decision"
        if link["body"].get("outcome") != "overturned":
            return False, "referenced decision did not overturn the action"
        action = self.enforcement.chain.get(link["body"].get("action_seq"))
        if action is None or action["kind"] != "enforcement.action":
            return False, "referenced decision does not resolve to an enforcement action"
        if not target or action["body"].get("subject") != target:
            return False, "decision concerns a different subject than the unban target"
        return True, "ok"

    # -- audit ---------------------------------------------------------

    def exception_report(self) -> list[dict]:
        """Every unban in the chain whose authorization does not resolve to
        an overturned decision. On a healthy system this list is empty; any
        entry is an exception someone must answer for -- by name."""
        out = []
        for link in self.chain.links():
            if link["kind"] != "admin.event":
                continue
            body = link.get("body", {})
            if body.get("event") != "unban":
                continue
            ok, reason = self._resolve_authorization(body.get("authorization"), body.get("target"))
            if not ok:
                out.append(
                    {
                        "seq": link["seq"],
                        "ts": link.get("ts"),
                        "staff_id": body.get("staff_id"),
                        "target": body.get("target"),
                        "reason": reason,
                    }
                )
        return out

    def report(self) -> dict:
        counts: dict = {}
        for link in self.chain.links():
            if link["kind"] == "admin.event":
                e = link["body"].get("event")
                counts[e] = counts.get(e, 0) + 1
        return {
            "events": counts,
            "unban_exceptions": len(self.exception_report()),
            "chain_valid": self.chain.verify()["valid"],
        }
