"""Article VI, Layer 3 -- the Ark: a triggered end-of-life instrument.

The commitment (package hash, license, trigger conditions) is sealed into
a public chain AT LAUNCH, so anyone can verify the escrow exists without
trusting anyone's word. Liveness is proven by sealed heartbeats; the
trigger is a pure function of public data -- evaluate() reads the chain
and a clock and returns triggered or not. No discretion in the loop.

Precedent context (verified Aug 2026): no studio has ever shipped this.
Ryzom's AGPL release proves irrevocable grants work; Loftia's "Ark"
pledge proves the promise is marketable; this module makes the promise a
verifiable instrument.

What code cannot do: hold the package. Custody of the Ark package (escrow
agent, attorney, foundation) is a legal instrument. This module makes the
COMMITMENT verifiable and the TRIGGER computable -- the parts that turn
"trust us" into "check for yourself."

Amendments are new commitment links (correctable, not erasable): the
current commitment is the latest one, and the history of every change to
the promise stays public.
"""
from __future__ import annotations

import hashlib
import re
from datetime import datetime

from .chain import Chain, ChainError, utc_now_iso

_SHA256_RE = re.compile(r"[0-9a-f]{64}")


def _parse_iso(ts: str) -> datetime:
    return datetime.fromisoformat(ts)


def _last_commitment_at_or_before(commitments: list, seq: int) -> dict:
    """The commitment in force at a given seq (commitments are seq-ascending)."""
    binding = commitments[0]
    for c in commitments:
        if c["seq"] <= seq:
            binding = c
        else:
            break
    return binding


class ArkInstrument:
    def __init__(self, chain: Chain):
        self.chain = chain

    # -- commitment ----------------------------------------------------

    def commit(
        self,
        package_sha256: str,
        license_id: str,
        heartbeat_interval_days: int,
        lapse_days: int,
        release_channels: list,
        version: str,
        note: str = "",
    ) -> dict:
        if not _SHA256_RE.fullmatch(package_sha256 or ""):
            raise ValueError("package_sha256 must be a sha256 hex digest of the Ark package")
        if not license_id:
            raise ValueError("license_id required (e.g. 'AGPL-3.0-or-later')")
        if not (
            isinstance(heartbeat_interval_days, int)
            and isinstance(lapse_days, int)
            and 0 < heartbeat_interval_days < lapse_days
        ):
            raise ValueError("require 0 < heartbeat_interval_days < lapse_days")
        if not release_channels:
            raise ValueError("at least one release channel required")
        prior = self.current_commitment()
        if prior is not None:
            pt = prior["body"]["trigger"]
            if lapse_days > pt["lapse_days"]:
                raise ValueError(
                    "an amendment may not lengthen lapse_days -- charter terms can only tighten"
                )
            if heartbeat_interval_days > pt["heartbeat_interval_days"]:
                raise ValueError(
                    "an amendment may not lengthen the heartbeat interval"
                )
        body = {
            "version": version,
            "package_sha256": package_sha256,
            "license": license_id,
            "trigger": {
                "heartbeat_interval_days": heartbeat_interval_days,
                "lapse_days": lapse_days,
                "explicit_cessation": True,
            },
            "release_channels": list(release_channels),
            "note": note,
        }
        return self.chain.append("ark.commitment", body)

    def current_commitment(self) -> dict | None:
        for link in reversed(self.chain.links()):
            if link["kind"] == "ark.commitment":
                return link
        return None

    # -- liveness ------------------------------------------------------

    def heartbeat(self, note: str = "") -> dict:
        if self.current_commitment() is None:
            raise ChainError("no Ark commitment sealed; nothing to keep alive")
        return self.chain.append("ark.heartbeat", {"note": note})

    def cease(self, statement: str) -> dict:
        """Explicit cessation: the honest shutdown path. Seals the trigger."""
        if not (statement or "").strip():
            raise ValueError("cessation requires a public statement")
        if self.current_commitment() is None:
            raise ChainError("no Ark commitment sealed")
        return self.chain.append("ark.cessation", {"statement": statement})

    # -- the trigger: pure function of public data ---------------------

    def evaluate(self, as_of: str | None = None) -> dict:
        """Has the Ark triggered? Computable by anyone from the chain alone.

        Triggered when EITHER an explicit cessation link exists, OR at any
        point up to `as_of` the gap between consecutive liveness signals
        (commitments and heartbeats) exceeded the lapse threshold.

        Two properties defeat a dishonest last-minute amendment (an operator
        abandoning the game, then appending a weaker commitment to escape):
          * the threshold used is the SMALLEST lapse_days ever committed, so
            terms can only tighten -- never widen retroactively; and
          * the trigger LATCHES -- a silence that already elapsed cannot be
            un-triggered by later activity, and the terms reported are those
            in force WHEN the silence began, not a package swapped in after.
        """
        links = self.chain.links()
        commitments = [l for l in links if l["kind"] == "ark.commitment"]
        if not commitments:
            return {"committed": False, "triggered": False, "reason": "no commitment sealed"}
        first = commitments[0]
        as_of_dt = _parse_iso(as_of or utc_now_iso())

        def terms(commitment: dict) -> dict:
            b = commitment["body"]
            return {
                "package_sha256": b["package_sha256"],
                "license": b["license"],
                "release_channels": b["release_channels"],
                "commitment_seq": commitment["seq"],
            }

        # explicit cessation: the honest shutdown path, always triggers
        for link in links:
            if link["kind"] == "ark.cessation" and link["seq"] > first["seq"]:
                binding = _last_commitment_at_or_before(commitments, link["seq"])
                return {
                    "committed": True,
                    "triggered": True,
                    "reason": "explicit cessation",
                    "cessation_seq": link["seq"],
                    **terms(binding),
                }

        # most player-favorable lapse threshold across every commitment
        effective_lapse = min(c["body"]["trigger"]["lapse_days"] for c in commitments)

        # liveness timeline from the first commitment onward
        events = sorted(
            (
                l for l in links
                if l["seq"] >= first["seq"] and l["kind"] in ("ark.commitment", "ark.heartbeat")
            ),
            key=lambda l: l["seq"],
        )
        prev = events[0]
        for cur in events[1:]:
            gap = (_parse_iso(cur["ts"]) - _parse_iso(prev["ts"])).total_seconds() / 86400.0
            if gap > effective_lapse:
                binding = _last_commitment_at_or_before(commitments, prev["seq"])
                return {
                    "committed": True,
                    "triggered": True,
                    "reason": (
                        f"{gap:.1f}-day silence exceeds lapse threshold of "
                        f"{effective_lapse} days"
                    ),
                    "days_since_heartbeat": round(gap, 1),
                    "lapse_days": effective_lapse,
                    **terms(binding),
                }
            prev = cur

        gap = (as_of_dt - _parse_iso(prev["ts"])).total_seconds() / 86400.0
        triggered = gap > effective_lapse
        binding = _last_commitment_at_or_before(commitments, prev["seq"])
        return {
            "committed": True,
            "triggered": triggered,
            "reason": (
                f"{gap:.1f} days since last liveness signal exceeds lapse threshold "
                f"of {effective_lapse} days"
                if triggered
                else "alive"
            ),
            "days_since_heartbeat": round(gap, 1),
            "lapse_days": effective_lapse,
            **terms(binding),
        }

    # -- package verification ------------------------------------------

    def verify_package(self, package_path: str) -> dict:
        """Does this file match the sealed commitment? Streamed sha256."""
        commitment = self.current_commitment()
        if commitment is None:
            raise ChainError("no Ark commitment sealed")
        h = hashlib.sha256()
        with open(package_path, "rb") as f:
            for block in iter(lambda: f.read(1 << 20), b""):
                h.update(block)
        actual = h.hexdigest()
        expected = commitment["body"]["package_sha256"]
        return {"match": actual == expected, "expected": expected, "actual": actual}
