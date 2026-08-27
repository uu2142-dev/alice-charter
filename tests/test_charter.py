"""Property tests for the charter-as-code package.

Each test proves a charter guarantee, not just code behavior:
tamper detection, correctable-not-erasable, gated reversals and unbans,
exact receipt splits against sealed sheets, the Ark trigger as a pure
function of public data, and independently verifiable player exports.
"""
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from charter import (  # noqa: E402
    AdminLedger,
    ArkInstrument,
    Chain,
    ChainError,
    EnforcementLedger,
    PlayerChain,
    ReceiptLedger,
    allocate,
    export_player,
    pseudonym,
)
from charter.chain import link_hash  # noqa: E402
import verify_charter  # noqa: E402


def _rewrite_line(path: str, seq: int, mutate):
    """Tamper helper: load the chain file, mutate the link at seq, rewrite."""
    with open(path, "r", encoding="utf-8") as f:
        links = [json.loads(l) for l in f if l.strip()]
    for link in links:
        if link["seq"] == seq:
            mutate(link)
    with open(path, "w", encoding="utf-8") as f:
        for link in links:
            f.write(json.dumps(link, sort_keys=True, ensure_ascii=False) + "\n")


class CharterTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = self._tmp.name

    def tearDown(self):
        self._tmp.cleanup()

    def _chain(self, name="test"):
        return Chain(os.path.join(self.dir, f"{name}.jsonl"), chain_id=name)

    # -- chain integrity ----------------------------------------------

    def test_chain_verifies_clean(self):
        c = self._chain()
        c.append("x", {"n": 1})
        c.append("x", {"n": 2})
        report = c.verify()
        self.assertTrue(report["valid"], report)
        self.assertEqual(report["links"], 3)

    def test_tamper_content_detected(self):
        c = self._chain()
        c.append("x", {"n": 1})
        _rewrite_line(c.path, 1, lambda l: l["body"].update(n=999))
        report = c.verify()
        self.assertFalse(report["valid"])
        self.assertEqual(report["first_bad_seq"], 1)
        self.assertIn("content hash mismatch", report["reason"])

    def test_tamper_rehash_detected_at_next_link(self):
        """Re-hashing a modified link moves the break to the NEXT link --
        the linkage property that makes silent edits impossible."""
        c = self._chain()
        c.append("x", {"n": 1})
        c.append("x", {"n": 2})

        def mutate(l):
            l["body"]["n"] = 999
            l["hash"] = link_hash(l)

        _rewrite_line(c.path, 1, mutate)
        report = c.verify()
        self.assertFalse(report["valid"])
        self.assertEqual(report["first_bad_seq"], 2)
        self.assertIn("linkage break", report["reason"])

    def test_deletion_detected(self):
        c = self._chain()
        c.append("x", {"n": 1})
        c.append("x", {"n": 2})
        with open(c.path, "r", encoding="utf-8") as f:
            lines = f.readlines()
        with open(c.path, "w", encoding="utf-8") as f:
            f.writelines(lines[:1] + lines[2:])  # drop seq 1
        report = c.verify()
        self.assertFalse(report["valid"])
        self.assertIn("sequence gap", report["reason"])

    def test_cross_chain_replay_detected(self):
        c = self._chain("alpha")
        c.append("x", {"n": 1})
        links = c.links()
        report = Chain.verify_links(links, chain_id="beta")
        self.assertFalse(report["valid"])
        self.assertIn("chain_id mismatch", report["reason"])

    # -- enforcement ---------------------------------------------------

    def _enf(self):
        led = EnforcementLedger(self._chain("enforcement"))
        led.publish_policy("p1", {"RMT_SELL": "Selling in-game value for money", "CHEAT": "Unauthorized software"})
        return led

    def test_action_requires_sealed_policy_reason(self):
        led = EnforcementLedger(self._chain("enforcement"))
        with self.assertRaises(ChainError):
            led.action("p_abc", "ban", "RMT_SELL", "0" * 64, "gm", "staff.jd")
        led.publish_policy("p1", {"RMT_SELL": "..."})
        with self.assertRaises(ValueError):
            led.action("p_abc", "ban", "UNPUBLISHED_REASON", "0" * 64, "gm", "staff.jd")

    def test_correctable_not_erasable(self):
        led = self._enf()
        act = led.action("p_abc", "ban", "RMT_SELL", "a" * 64, "gm", "staff.jd")
        ap = led.appeal("p_abc", act["seq"], "I didn't do it")
        led.decide(ap["seq"], "overturned", "reviewer.x", "Evidence was for a different account")
        kinds = [l["kind"] for l in led.chain.links()]
        # original action still present alongside the reversal
        self.assertIn("enforcement.action", kinds)
        self.assertIn("enforcement.reversal", kinds)
        report = led.transparency_report()
        self.assertEqual(report["overturned"], 1)
        self.assertEqual(report["overturn_rate"], 1.0)
        self.assertTrue(report["chain_valid"])

    def test_appeal_subject_must_match(self):
        led = self._enf()
        act = led.action("p_abc", "ban", "RMT_SELL", "a" * 64, "gm", "staff.jd")
        with self.assertRaises(ChainError):
            led.appeal("p_other", act["seq"])

    def test_appeal_cannot_be_decided_twice(self):
        led = self._enf()
        act = led.action("p_abc", "suspend", "CHEAT", "b" * 64, "gm", "staff.jd")
        ap = led.appeal("p_abc", act["seq"])
        led.decide(ap["seq"], "upheld", "reviewer.x", "Evidence stands")
        with self.assertRaises(ChainError):
            led.decide(ap["seq"], "overturned", "reviewer.y", "Trying again")

    def test_audit_flags_rogue_reversal(self):
        """A reversal appended around the API (raw chain write) is caught by
        the semantic audit even though the hash chain stays valid."""
        led = self._enf()
        act = led.action("p_abc", "ban", "RMT_SELL", "a" * 64, "gm", "staff.jd")
        led.chain.append(
            "enforcement.reversal",
            {"action_seq": act["seq"], "action_hash": act["hash"], "decision_seq": 999,
             "decision_hash": "f" * 64, "subject": "p_abc"},
        )
        self.assertTrue(led.chain.verify()["valid"])  # hashes fine...
        violations = led.audit()  # ...semantics not
        self.assertEqual(len(violations), 1)
        self.assertIn("overturned decision", violations[0]["reason"])

    def test_audit_clean_on_honest_chain(self):
        led = self._enf()
        act = led.action("p_abc", "ban", "RMT_SELL", "a" * 64, "gm", "staff.jd")
        ap = led.appeal("p_abc", act["seq"])
        led.decide(ap["seq"], "overturned", "reviewer.x", "Mistaken identity")
        self.assertEqual(led.audit(), [])

    def test_audit_flags_decision_action_mismatch(self):
        """A forged 'overturned' decision citing a real appeal but pointing at
        a DIFFERENT, un-appealed action cannot launder a reversal.
        (Regression: review finding #2 -- decision action_seq unchecked.)"""
        led = self._enf()
        a_victim = led.action("p_victim", "ban", "RMT_SELL", "a" * 64, "gm", "staff.jd")
        a_other = led.action("p_other", "ban", "RMT_SELL", "b" * 64, "gm", "staff.jd")
        ap = led.appeal("p_victim", a_victim["seq"])
        # rogue decision: cites the real appeal's hash but a_other's seq
        d2 = led.chain.append(
            "enforcement.decision",
            {"appeal_seq": ap["seq"], "appeal_hash": ap["hash"], "action_seq": a_other["seq"],
             "outcome": "overturned", "reviewer_id": "staff.insider", "rationale": "-"},
        )
        led.chain.append(
            "enforcement.reversal",
            {"action_seq": a_other["seq"], "action_hash": a_other["hash"],
             "decision_seq": d2["seq"], "decision_hash": d2["hash"], "subject": "p_other"},
        )
        self.assertTrue(led.chain.verify()["valid"])  # hashes fine
        violations = led.audit()  # semantics not
        self.assertTrue(any("action_seq does not match" in v["reason"] for v in violations),
                        violations)

    def test_audit_flags_duplicate_decision(self):
        """An appeal cannot be decided twice via a raw-appended second decision.
        (Regression: review finding #2 -- one-decision-per-appeal unchecked.)"""
        led = self._enf()
        act = led.action("p_abc", "suspend", "CHEAT", "b" * 64, "gm", "staff.jd")
        ap = led.appeal("p_abc", act["seq"])
        led.decide(ap["seq"], "upheld", "reviewer.x", "Evidence stands")
        led.chain.append(
            "enforcement.decision",
            {"appeal_seq": ap["seq"], "appeal_hash": ap["hash"], "action_seq": act["seq"],
             "outcome": "overturned", "reviewer_id": "staff.insider", "rationale": "second bite"},
        )
        violations = led.audit()
        self.assertTrue(any("already resolved" in v["reason"] for v in violations), violations)

    def test_pseudonym_stable_and_salted(self):
        a1 = pseudonym("salt1", "account42")
        a2 = pseudonym("salt1", "account42")
        b = pseudonym("salt2", "account42")
        self.assertEqual(a1, a2)
        self.assertNotEqual(a1, b)
        self.assertEqual(len(a1), 16)

    # -- admin telemetry -----------------------------------------------

    def test_unban_refused_without_authorization(self):
        enf = self._enf()
        adm = AdminLedger(self._chain("admin"), enforcement=enf)
        with self.assertRaises(ChainError):
            adm.log("unban", "staff.jd", "friend asked nicely", target="p_abc")

    def test_unban_allowed_with_overturned_decision(self):
        enf = self._enf()
        adm = AdminLedger(self._chain("admin"), enforcement=enf)
        act = enf.action("p_abc", "ban", "RMT_SELL", "a" * 64, "gm", "staff.jd")
        ap = enf.appeal("p_abc", act["seq"])
        dec = enf.decide(ap["seq"], "overturned", "reviewer.x", "Wrong account")
        link = adm.log(
            "unban", "staff.jd", "appeal overturned", target="p_abc",
            authorization={"decision_seq": dec["seq"], "decision_hash": dec["hash"]},
        )
        self.assertEqual(link["body"]["event"], "unban")
        self.assertEqual(adm.exception_report(), [])

    def test_exception_report_catches_bypassed_unban(self):
        """The Ashes query: an unban written around the gate shows up, by
        name, in the exception report."""
        enf = self._enf()
        adm = AdminLedger(self._chain("admin"), enforcement=enf)
        adm.chain.append(
            "admin.event",
            {"event": "unban", "staff_id": "staff.insider", "justification": "-",
             "target": "p_friend", "params": {}},
        )
        exceptions = adm.exception_report()
        self.assertEqual(len(exceptions), 1)
        self.assertEqual(exceptions[0]["staff_id"], "staff.insider")
        self.assertEqual(exceptions[0]["target"], "p_friend")

    def test_unban_authorization_bound_to_target(self):
        """One player's overturn cannot launder an unban for another player.
        (Regression: review finding #1 -- target-blind authorization.)"""
        enf = self._enf()
        adm = AdminLedger(self._chain("admin"), enforcement=enf)
        act = enf.action("p_victim", "ban", "RMT_SELL", "a" * 64, "gm", "staff.jd")
        ap = enf.appeal("p_victim", act["seq"])
        dec = enf.decide(ap["seq"], "overturned", "reviewer.x", "Wrong account")
        auth = {"decision_seq": dec["seq"], "decision_hash": dec["hash"]}
        # the legitimate subject: allowed
        adm.log("unban", "staff.jd", "appeal overturned", target="p_victim", authorization=auth)
        # a different player, same real overturn: refused
        with self.assertRaises(ChainError):
            adm.log("unban", "staff.insider", "favor", target="p_friend", authorization=auth)
        # and a bypass write reusing the reference is caught by the audit
        adm.chain.append(
            "admin.event",
            {"event": "unban", "staff_id": "staff.insider", "justification": "favor",
             "target": "p_friend", "params": {}, "authorization": auth},
        )
        exceptions = adm.exception_report()
        self.assertEqual([e["target"] for e in exceptions], ["p_friend"])

    def test_justification_required(self):
        adm = AdminLedger(self._chain("admin"))
        with self.assertRaises(ValueError):
            adm.log("item_spawn", "staff.jd", "   ", target="p_abc")

    def test_data_query_is_telemetry(self):
        adm = AdminLedger(self._chain("admin"))
        link = adm.log("data_query", "staff.jd", "GDPR export request", target="p_abc",
                       params={"scope": "full_history"})
        self.assertEqual(link["body"]["event"], "data_query")

    # -- receipts ------------------------------------------------------

    def test_allocate_exact_and_deterministic(self):
        ratios = {"server": 0.30, "development": 0.40, "steward": 0.20, "reserve": 0.10}
        for gross in (0, 1, 2, 3, 99, 100, 101, 1999, 2999, 12345, 9999999):
            split = allocate(gross, ratios)
            self.assertEqual(sum(split.values()), gross, f"gross={gross}")
        self.assertEqual(allocate(100, ratios),
                         {"server": 30, "development": 40, "steward": 20, "reserve": 10})

    def test_allocate_rejects_out_of_range_ratios(self):
        """Ratios that net to 1.0 but include negatives / >1 must be rejected,
        or an operator routes >100% to one bucket and negative to another while
        the sum still checks out. (Regression: review finding #3.)"""
        bad = {"server": 2.0, "development": -1.0, "steward": 0.0, "reserve": 0.0}
        with self.assertRaises(ValueError):
            allocate(2999, bad)
        led = ReceiptLedger(self._chain("receipts"))
        with self.assertRaises(ValueError):
            led.publish_price_sheet("2026-08", {"game.base": 2999}, bad)

    def test_purchase_requires_sealed_sheet_and_sku(self):
        led = ReceiptLedger(self._chain("receipts"))
        with self.assertRaises(ChainError):
            led.purchase("p_buyer", "game.base")
        led.publish_price_sheet(
            "2026-08", {"game.base": 2999, "cosmetic.lantern": 499},
            {"server": 0.30, "development": 0.40, "steward": 0.20, "reserve": 0.10},
        )
        with self.assertRaises(ChainError):
            led.purchase("p_buyer", "sku.not.on.sheet")
        r = led.purchase("p_buyer", "game.base")
        self.assertEqual(r["body"]["gross_cents"], 2999)
        self.assertEqual(sum(r["body"]["splits_cents"].values()), 2999)

    def test_receipt_summary_and_audit_clean(self):
        led = ReceiptLedger(self._chain("receipts"))
        led.publish_price_sheet(
            "2026-08", {"game.base": 2999},
            {"server": 0.30, "development": 0.40, "steward": 0.20, "reserve": 0.10},
        )
        for i in range(5):
            led.purchase(f"p_buyer{i}", "game.base")
        s = led.summary()
        self.assertEqual(s["purchases"], 5)
        self.assertEqual(s["gross_cents"], 5 * 2999)
        self.assertTrue(s["splits_sum_ok"])
        self.assertEqual(led.audit(), [])

    def test_receipt_audit_catches_forged_split(self):
        led = ReceiptLedger(self._chain("receipts"))
        sheet = led.publish_price_sheet(
            "2026-08", {"game.base": 2999},
            {"server": 0.30, "development": 0.40, "steward": 0.20, "reserve": 0.10},
        )
        led.chain.append(
            "receipt.purchase",
            {"buyer": "p_x", "sku": "game.base", "gross_cents": 2999,
             "splits_cents": {"server": 0, "development": 2999, "steward": 0, "reserve": 0},
             "sheet_seq": sheet["seq"], "sheet_hash": sheet["hash"]},
        )
        violations = led.audit()
        self.assertEqual(len(violations), 1)
        self.assertIn("splits do not match", violations[0]["reason"])

    # -- ark -----------------------------------------------------------

    def _ark(self):
        ark = ArkInstrument(self._chain("ark"))
        ark.commit("c" * 64, "AGPL-3.0-or-later", 30, 180,
                   ["public-repo", "archive-org"], "1.0")
        return ark

    def test_ark_alive_with_recent_heartbeat(self):
        ark = self._ark()
        ark.heartbeat("monthly liveness")
        status = ark.evaluate()
        self.assertTrue(status["committed"])
        self.assertFalse(status["triggered"])

    def test_ark_triggers_on_lapse(self):
        ark = self._ark()
        status = ark.evaluate(as_of="2027-06-01T00:00:00+00:00")
        self.assertTrue(status["triggered"])
        self.assertIn("exceeds lapse threshold", status["reason"])
        self.assertEqual(status["package_sha256"], "c" * 64)

    def test_ark_triggers_on_cessation(self):
        ark = self._ark()
        ark.cease("Studio is closing; the Ark releases as committed.")
        status = ark.evaluate()
        self.assertTrue(status["triggered"])
        self.assertEqual(status["reason"], "explicit cessation")

    def test_ark_package_verification(self):
        ark = ArkInstrument(self._chain("ark"))
        pkg = os.path.join(self.dir, "ark_package.zip")
        with open(pkg, "wb") as f:
            f.write(b"the whole game, sealed")
        import hashlib
        digest = hashlib.sha256(b"the whole game, sealed").hexdigest()
        ark.commit(digest, "AGPL-3.0-or-later", 30, 180, ["public-repo"], "1.0")
        self.assertTrue(ark.verify_package(pkg)["match"])
        with open(pkg, "ab") as f:
            f.write(b" -- tampered")
        self.assertFalse(ark.verify_package(pkg)["match"])

    def test_ark_trigger_params_validated(self):
        ark = ArkInstrument(self._chain("ark"))
        with self.assertRaises(ValueError):
            ark.commit("c" * 64, "AGPL-3.0-or-later", 180, 30, ["repo"], "1.0")

    def test_ark_amendment_cannot_lengthen_lapse(self):
        """The API refuses to weaken the promise. (Regression: review #4.)"""
        ark = self._ark()  # lapse_days 180
        with self.assertRaises(ValueError):
            ark.commit("d" * 64, "Proprietary", 30, 999999, ["repo"], "2.0")

    def test_ark_late_amendment_cannot_escape_lapse(self):
        """A raw-appended amendment after a long silence cannot un-trigger a
        lapse that already elapsed, nor swap in a weaker package: evaluate()
        latches and reports the terms in force when the silence began.
        (Regression: review finding #4 -- clock reset + term rewrite.)"""
        chain = self._chain("ark")
        ark = ArkInstrument(chain)
        ark.commit("c" * 64, "AGPL-3.0-or-later", 30, 180, ["public-repo"], "1.0")
        # operator goes dark, then ~1 year later appends a weaker amendment
        tip = chain.tip()
        amendment = {
            "schema": 1, "chain_id": chain.chain_id, "seq": tip["seq"] + 1,
            "kind": "ark.commitment", "ts": "2027-08-16T00:00:00+00:00",
            "prev_hash": tip["hash"],
            "body": {"version": "2.0", "package_sha256": "0" * 64, "license": "Proprietary",
                     "trigger": {"heartbeat_interval_days": 30, "lapse_days": 999999,
                                 "explicit_cessation": True},
                     "release_channels": ["public-repo"], "note": "escape attempt"},
        }
        amendment["hash"] = link_hash(amendment)
        chain._append_line(amendment)
        status = ark.evaluate(as_of="2027-08-16T01:00:00+00:00")
        self.assertTrue(status["triggered"])
        # the 999999-day threshold and worthless package did NOT take effect
        self.assertEqual(status["lapse_days"], 180)
        self.assertEqual(status["package_sha256"], "c" * 64)
        self.assertEqual(status["license"], "AGPL-3.0-or-later")

    # -- player export -------------------------------------------------

    def test_player_export_verifies_standalone(self):
        pc = PlayerChain(self.dir, "p_abc123")
        pc.record("session_start", {"world": "north-ridge"})
        pc.record("trade", {"gave": "sulfur x1000", "got": "rocket x2"},
                  occurred_at="2026-08-16T03:00:00+00:00")
        out = os.path.join(self.dir, "export.json")
        export_player(pc, out)
        loaded = verify_charter.load(out)
        report = verify_charter.verify_links(loaded["links"], chain_id=loaded["chain_id"])
        self.assertTrue(report["valid"], report)
        self.assertTrue(all(loaded["extra"].values()))

    def test_tampered_export_fails_standalone_verify(self):
        pc = PlayerChain(self.dir, "p_abc123")
        pc.record("session_start", {"world": "north-ridge"})
        out = os.path.join(self.dir, "export.json")
        export_player(pc, out)
        with open(out, "r", encoding="utf-8") as f:
            doc = json.load(f)
        doc["links"][1]["body"]["data"]["world"] = "rewritten-history"
        with open(out, "w", encoding="utf-8") as f:
            json.dump(doc, f)
        loaded = verify_charter.load(out)
        report = verify_charter.verify_links(loaded["links"], chain_id=loaded["chain_id"])
        self.assertFalse(report["valid"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
