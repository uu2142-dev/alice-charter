#!/usr/bin/env python3
"""Standalone charter chain verifier.

Pure stdlib, ZERO imports from the charter package -- so anyone can verify
a chain file or a player export with nothing but Python. This duplication
is deliberate: the verifier must not depend on the code it checks.

Usage:
    python verify_charter.py <chain.jsonl | export.json>

Exit code 0 = verifies; 1 = does not.

Canonicalization (must match charter/chain.py exactly):
    hash = sha256( json.dumps(link_minus_hash, sort_keys=True,
                   separators=(",", ":"), ensure_ascii=False).encode("utf-8") )
"""
from __future__ import annotations

import hashlib
import json
import sys

GENESIS_KIND = "genesis"


def _canonical(obj) -> bytes:
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def _link_hash(link: dict) -> str:
    body = {k: v for k, v in link.items() if k != "hash"}
    return hashlib.sha256(_canonical(body)).hexdigest()


def verify_links(links: list, chain_id: str | None = None) -> dict:
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
        if _link_hash(link) != link.get("hash"):
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


def load(path: str) -> dict:
    """Load either a raw .jsonl chain or a player-export .json document.
    Returns {"links": [...], "chain_id": str|None, "extra": {...}}."""
    if path.endswith(".json"):
        with open(path, "r", encoding="utf-8") as f:
            doc = json.load(f)
        links = doc.get("links", [])
        extra = {}
        if "tip_hash" in doc and links:
            extra["tip_hash_ok"] = doc["tip_hash"] == links[-1].get("hash")
        return {"links": links, "chain_id": doc.get("chain_id"), "extra": extra}
    links = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                links.append(json.loads(line))
    return {"links": links, "chain_id": None, "extra": {}}


def main(argv: list) -> int:
    if len(argv) != 1:
        print(__doc__)
        return 1
    loaded = load(argv[0])
    report = verify_links(loaded["links"], chain_id=loaded["chain_id"])
    ok = report["valid"] and all(loaded["extra"].values())
    print(f"file:        {argv[0]}")
    if loaded["chain_id"]:
        print(f"chain_id:    {loaded['chain_id']}")
    print(f"links:       {report['links']}")
    for k, v in loaded["extra"].items():
        print(f"{k}: {'ok' if v else 'MISMATCH'}")
    print(f"verdict:     {'VALID -- ' + report['reason'] if report['valid'] else 'INVALID -- ' + report['reason']}")
    if report["first_bad_seq"] is not None:
        print(f"first bad:   seq {report['first_bad_seq']}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
