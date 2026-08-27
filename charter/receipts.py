"""Article V -- open unit economics.

The Verum receipt model applied to game revenue. Deterministic gates:

  * A purchase can only be recorded against a SEALED price sheet -- you
    cannot charge a price you never published.
  * The split into server / development / steward / reserve is computed
    from the sealed sheet's ratios in integer cents, and must sum to the
    gross EXACTLY. allocate() uses largest-remainder so rounding can never
    create or destroy a cent.
  * audit() recomputes every receipt against its referenced sheet.
"""
from __future__ import annotations

from .chain import Chain, ChainError, canonical, sha256_hex

SPLIT_KEYS = ("server", "development", "steward", "reserve")


def allocate(gross_cents: int, ratios: dict) -> dict:
    """Split gross_cents by ratios into integer cents summing exactly.

    Largest-remainder method; deterministic tie-break by SPLIT_KEYS order.
    """
    if not isinstance(gross_cents, int) or gross_cents < 0:
        raise ValueError("gross_cents must be a non-negative integer")
    if set(ratios) != set(SPLIT_KEYS):
        raise ValueError(f"ratios must have exactly the keys {SPLIT_KEYS}")
    if any(not (0.0 <= r <= 1.0) for r in ratios.values()):
        raise ValueError("each split ratio must be within [0, 1]")
    total = sum(ratios.values())
    if abs(total - 1.0) > 1e-9:
        raise ValueError(f"split ratios must sum to 1.0 (got {total})")
    raw = {k: gross_cents * ratios[k] for k in SPLIT_KEYS}
    floors = {k: int(raw[k]) for k in SPLIT_KEYS}
    remainder = gross_cents - sum(floors.values())
    order = sorted(
        SPLIT_KEYS, key=lambda k: (-(raw[k] - floors[k]), SPLIT_KEYS.index(k))
    )
    for k in order[:remainder]:
        floors[k] += 1
    return floors


class ReceiptLedger:
    def __init__(self, chain: Chain):
        self.chain = chain

    # -- price sheets --------------------------------------------------

    def publish_price_sheet(self, version: str, items: dict, split_ratios: dict) -> dict:
        """Seal a price sheet: {sku: price_in_cents} plus the split ratios."""
        if not version:
            raise ValueError("price sheet version required")
        if not items:
            raise ValueError("price sheet must contain at least one sku")
        for sku, cents in items.items():
            if not isinstance(cents, int) or cents < 0:
                raise ValueError(f"price for {sku!r} must be non-negative integer cents")
        allocate(0, split_ratios)  # validates keys and ratio sum
        body = {
            "version": version,
            "items": dict(sorted(items.items())),
            "split_ratios": {k: split_ratios[k] for k in SPLIT_KEYS},
        }
        body["sheet_sha256"] = sha256_hex(
            canonical({"items": body["items"], "split_ratios": body["split_ratios"]})
        )
        return self.chain.append("receipt.price_sheet", body)

    def current_sheet(self) -> dict | None:
        for link in reversed(self.chain.links()):
            if link["kind"] == "receipt.price_sheet":
                return link
        return None

    # -- purchases -----------------------------------------------------

    def purchase(self, buyer: str, sku: str, occurred_at: str | None = None) -> dict:
        """Record a purchase at the sealed price, with the sealed split."""
        if not buyer:
            raise ValueError("buyer pseudonym required")
        sheet = self.current_sheet()
        if sheet is None:
            raise ChainError("no sealed price sheet; call publish_price_sheet() first")
        items = sheet["body"]["items"]
        if sku not in items:
            raise ChainError(
                f"sku {sku!r} is not on sealed price sheet {sheet['body']['version']}"
            )
        gross = items[sku]
        splits = allocate(gross, sheet["body"]["split_ratios"])
        body = {
            "buyer": buyer,
            "sku": sku,
            "gross_cents": gross,
            "splits_cents": splits,
            "sheet_seq": sheet["seq"],
            "sheet_hash": sheet["hash"],
        }
        return self.chain.append("receipt.purchase", body, occurred_at=occurred_at)

    # -- transparency --------------------------------------------------

    def summary(self) -> dict:
        totals = {k: 0 for k in SPLIT_KEYS}
        gross = 0
        count = 0
        by_sku: dict = {}
        for link in self.chain.links():
            if link["kind"] != "receipt.purchase":
                continue
            b = link["body"]
            count += 1
            gross += b["gross_cents"]
            by_sku[b["sku"]] = by_sku.get(b["sku"], 0) + 1
            for k in SPLIT_KEYS:
                totals[k] += b["splits_cents"].get(k, 0)
        return {
            "purchases": count,
            "gross_cents": gross,
            "splits_cents": totals,
            "by_sku": by_sku,
            "splits_sum_ok": gross == sum(totals.values()),
            "chain_valid": self.chain.verify()["valid"],
        }

    # -- semantic audit ------------------------------------------------

    def audit(self) -> list[dict]:
        """Recompute every receipt against its referenced sealed sheet.
        Flags: dangling sheet references, prices not on the sheet, splits
        that do not match allocate(gross, sealed ratios)."""
        links = self.chain.links()
        by_seq = {l["seq"]: l for l in links}
        violations: list[dict] = []
        for link in links:
            if link["kind"] != "receipt.purchase":
                continue
            b = link.get("body", {})
            sheet = by_seq.get(b.get("sheet_seq"))
            if (
                sheet is None
                or sheet["kind"] != "receipt.price_sheet"
                or sheet["hash"] != b.get("sheet_hash")
                or sheet["seq"] > link["seq"]
            ):
                violations.append(
                    {"seq": link["seq"], "reason": "receipt does not trace to a sealed price sheet"}
                )
                continue
            items = sheet["body"]["items"]
            sku = b.get("sku")
            if sku not in items or b.get("gross_cents") != items[sku]:
                violations.append(
                    {"seq": link["seq"], "reason": "receipt price does not match sealed sheet"}
                )
                continue
            expected = allocate(items[sku], sheet["body"]["split_ratios"])
            if b.get("splits_cents") != expected:
                violations.append(
                    {"seq": link["seq"], "reason": "receipt splits do not match sealed ratios"}
                )
        return violations
