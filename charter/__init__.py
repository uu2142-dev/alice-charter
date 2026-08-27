"""Charter-as-code: the executable articles of The Unruggable Game charter.

Two-layer verification model used by every ledger:
  chain.verify()  -- INTEGRITY: nobody rewrote history (hash linkage).
  ledger.audit()  -- SEMANTICS: nobody abused power within valid history
                     (reversals trace to decisions, receipts to sealed
                     sheets, unbans to overturned decisions).
"""
from .chain import Chain, ChainError, canonical, link_hash, sha256_hex, utc_now_iso
from .enforcement import ACTIONS, APPEAL_OUTCOMES, EnforcementLedger, pseudonym
from .admin_telemetry import EVENTS, AdminLedger
from .receipts import SPLIT_KEYS, ReceiptLedger, allocate
from .ark import ArkInstrument
from .player_export import EXPORT_FORMAT, PlayerChain, export_player

__all__ = [
    "Chain",
    "ChainError",
    "canonical",
    "link_hash",
    "sha256_hex",
    "utc_now_iso",
    "ACTIONS",
    "APPEAL_OUTCOMES",
    "EnforcementLedger",
    "pseudonym",
    "EVENTS",
    "AdminLedger",
    "SPLIT_KEYS",
    "ReceiptLedger",
    "allocate",
    "ArkInstrument",
    "EXPORT_FORMAT",
    "PlayerChain",
    "export_player",
]
