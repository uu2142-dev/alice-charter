"""Sealed hash-chain primitive shared by every charter ledger.

Kernel-as-code: the chain is deterministic code -- no model in the loop.
Links are append-only JSON lines in a .jsonl file. Corrections are NEW
links that reference old ones (correctable, not erasable). Verification
needs nothing but this file's canonicalization rules and SHA-256.

Canonical form (the bytes that get hashed) of a link:
    json.dumps({...link minus "hash"...}, sort_keys=True,
               separators=(",", ":"), ensure_ascii=False).encode("utf-8")

The signature layer (Ed25519 over tip hashes, external anchoring of
roots) is deliberately pluggable and NOT implemented here: the chain's
guarantee is hash linkage. Publishing the tip hash outside the operator's
control is what makes silent truncation detectable -- see README.
"""
from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timezone

SCHEMA_VERSION = 1
GENESIS_KIND = "genesis"


class ChainError(Exception):
    """Raised when a chain operation would violate charter guarantees."""


def canonical(obj) -> bytes:
    """Canonical JSON bytes used for every hash in the charter."""
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def link_hash(link: dict) -> str:
    """Hash of a link's canonical form, excluding its own hash field."""
    body = {k: v for k, v in link.items() if k != "hash"}
    return sha256_hex(canonical(body))


class Chain:
    """Append-only, hash-linked JSONL ledger.

    Every link carries the chain_id, so a link cannot be replayed into a
    different chain without breaking verification.
    """

    def __init__(self, path: str, chain_id: str):
        self.path = path
        self.chain_id = chain_id
        if not os.path.exists(path) or os.path.getsize(path) == 0:
            self._write_genesis()

    # -- write ---------------------------------------------------------

    def _write_genesis(self) -> None:
        link = {
            "schema": SCHEMA_VERSION,
            "chain_id": self.chain_id,
            "seq": 0,
            "kind": GENESIS_KIND,
            "ts": utc_now_iso(),
            "body": {},
            "prev_hash": "",
        }
        link["hash"] = link_hash(link)
        self._append_line(link)

    def _append_line(self, link: dict) -> None:
        parent = os.path.dirname(os.path.abspath(self.path))
        os.makedirs(parent, exist_ok=True)
        with open(self.path, "a", encoding="utf-8") as f:
            f.write(json.dumps(link, sort_keys=True, ensure_ascii=False) + "\n")

    def append(self, kind: str, body: dict, occurred_at: str | None = None) -> dict:
        """Seal a new link. `occurred_at` records client event time when it
        differs from seal time (offline queues sync later -- the event time
        is real, the seal time is when the chain saw it)."""
        if not kind or kind == GENESIS_KIND:
            raise ChainError(f"invalid kind: {kind!r}")
        if not isinstance(body, dict):
            raise ChainError("body must be a dict")
        tip = self.tip()
        link = {
            "schema": SCHEMA_VERSION,
            "chain_id": self.chain_id,
            "seq": tip["seq"] + 1,
            "kind": kind,
            "ts": utc_now_iso(),
            "body": body,
            "prev_hash": tip["hash"],
        }
        if occurred_at is not None:
            link["occurred_at"] = occurred_at
        link["hash"] = link_hash(link)
        self._append_line(link)
        return link

    # -- read ----------------------------------------------------------

    def links(self) -> list[dict]:
        out = []
        with open(self.path, "r", encoding="utf-8") as f:
            for n, line in enumerate(f):
                line = line.strip()
                if not line:
                    continue
                try:
                    out.append(json.loads(line))
                except json.JSONDecodeError as e:
                    raise ChainError(f"line {n + 1}: not valid JSON: {e}") from e
        return out

    def tip(self) -> dict:
        links = self.links()
        if not links:
            raise ChainError("empty chain (no genesis)")
        return links[-1]

    def get(self, seq: int) -> dict | None:
        for link in self.links():
            if link.get("seq") == seq:
                return link
        return None

    # -- verify --------------------------------------------------------

    @staticmethod
    def verify_links(links: list[dict], chain_id: str | None = None) -> dict:
        """Full independent re-verification of a link list.

        Detects: content edits (hash mismatch), re-hashed edits (linkage
        break at the next link), reordering / deletion (sequence gap),
        cross-chain replay (chain_id mismatch), forged genesis.
        """
        report = {"valid": False, "links": len(links), "first_bad_seq": None, "reason": ""}
        if not links:
            report["reason"] = "no links"
            return report
        prev = None
        for i, link in enumerate(links):
            seq = link.get("seq")
            if seq != i:
                report.update(first_bad_seq=seq, reason=f"sequence gap: expected {i}, got {seq}")
                return report
            if chain_id is not None and link.get("chain_id") != chain_id:
                report.update(first_bad_seq=seq, reason=f"chain_id mismatch at seq {seq}")
                return report
            if link_hash(link) != link.get("hash"):
                report.update(first_bad_seq=seq, reason=f"content hash mismatch at seq {seq}")
                return report
            if i == 0:
                if link.get("kind") != GENESIS_KIND or link.get("prev_hash") != "":
                    report.update(first_bad_seq=seq, reason="invalid genesis link")
                    return report
            else:
                if link.get("prev_hash") != prev["hash"]:
                    report.update(first_bad_seq=seq, reason=f"linkage break at seq {seq}")
                    return report
            prev = link
        report["valid"] = True
        report["reason"] = "ok"
        return report

    def verify(self) -> dict:
        return Chain.verify_links(self.links(), chain_id=self.chain_id)
