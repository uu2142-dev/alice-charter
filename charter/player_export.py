"""Article VI, Layer 1 -- your record leaves with you.

A player's history is its own chain; export_player() writes a single
self-contained JSON file that verify_charter.py (pure stdlib, zero
imports from this package) can verify anywhere, forever. Your history is
yours even if every server burns.
"""
from __future__ import annotations

import json
import os

from .chain import Chain, utc_now_iso

EXPORT_FORMAT = "charter-player-export/v1"


class PlayerChain:
    """Per-player sealed event chain."""

    def __init__(self, directory: str, player_pseudonym: str):
        if not player_pseudonym:
            raise ValueError("player pseudonym required")
        self.player = player_pseudonym
        self.chain = Chain(
            os.path.join(directory, f"player_{player_pseudonym}.jsonl"),
            chain_id=f"player:{player_pseudonym}",
        )

    def record(self, event_type: str, data: dict, occurred_at: str | None = None) -> dict:
        if not event_type:
            raise ValueError("event_type required")
        return self.chain.append(
            "player.event", {"type": event_type, "data": data}, occurred_at=occurred_at
        )


def export_player(player_chain: PlayerChain, out_path: str) -> dict:
    """Write the player's complete chain as one verifiable file."""
    links = player_chain.chain.links()
    doc = {
        "format": EXPORT_FORMAT,
        "exported_at": utc_now_iso(),
        "chain_id": player_chain.chain.chain_id,
        "tip_hash": links[-1]["hash"],
        "links": links,
    }
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(doc, f, ensure_ascii=False, indent=2)
    return doc
