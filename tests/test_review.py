from copy import deepcopy
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from firewall_auditor.agent import audit
from firewall_auditor.core import load_policy
from firewall_auditor.demo import REVIEW_POLICY, match, review_snapshot
from firewall_auditor.report import report_html


def prefix(address, length):
    return {"prefix": {"addr": address, "len": length}}


class ReviewTests(unittest.TestCase):
    def run_review(self, evidence, policy, model=None):
        with TemporaryDirectory() as directory:
            return audit(evidence, load_policy(policy), model, Path(directory) / "audit.jsonl")

    def test_five_cases_and_independent_fixes(self):
        evidence = review_snapshot()
        report = self.run_review(evidence, REVIEW_POLICY)
        self.assertEqual(len(report["findings"]), 5)
        by_handle = {item["rule"]["handle"]: item for item in report["findings"]}
        self.assertEqual(set(by_handle), {11, 12, 13, 14, 18})
        self.assertEqual(by_handle[18]["sets"], ["@team_clients"])
        self.assertTrue(by_handle[18]["via"])
        self.assertEqual(by_handle[18]["sources"], ["198.51.100.0/25"])
        repairs = {
            11: [match("ip", "saddr", "192.0.2.8"), match("tcp", "dport", 22), {"accept": None}],
            12: [{"drop": None}],
            13: [match("ip", "saddr", "192.0.2.55"), match("tcp", "dport", 8080), {"accept": None}],
            14: [match("ip6", "saddr", prefix("2001:db8:10::", 64)),
                 match("tcp", "dport", 8443), {"accept": None}],
            18: [match("ip", "saddr", "198.51.100.7"), match("tcp", "dport", 9443), {"accept": None}],
        }
        for handle, repair in repairs.items():
            with self.subTest(handle=handle):
                fixed = deepcopy(evidence)
                for entry in fixed["ruleset"]["nftables"]:
                    rule = entry.get("rule", {})
                    if rule.get("handle") == handle:
                        rule["expr"] = repair
                result = self.run_review(fixed, REVIEW_POLICY)
                self.assertEqual({item["rule"]["handle"] for item in result["findings"]},
                                 set(by_handle) - {handle})

    def test_renamed_table_and_ambiguous_jump(self):
        evidence = review_snapshot()
        entries = evidence["ruleset"]["nftables"]
        for entry in entries:
            item = next(iter(entry.values()))
            if "table" in item:
                item["table"] = "an_unfamiliar_table"
        entries.reverse()
        self.assertEqual(len(self.run_review(evidence, REVIEW_POLICY)["findings"]), 5)
        jump = deepcopy(next(entry for entry in entries if entry.get("rule", {}).get("handle") == 17))
        jump["rule"]["handle"] = 99
        entries.append(jump)
        report = self.run_review(evidence, REVIEW_POLICY)
        self.assertEqual(len(report["findings"]), 4)
        self.assertIn("manual review", " ".join(report["gaps"]).lower())

    def test_dynamic_sets_and_disjoint_jump_scopes_do_not_create_findings(self):
        source = review_snapshot()
        entries = source["ruleset"]["nftables"]
        definition = next(entry["set"] for entry in entries if "set" in entry)
        definition["flags"].append("timeout")
        result = self.run_review(source, REVIEW_POLICY)
        self.assertEqual(len(result["findings"]), 4)
        self.assertTrue(any(not rule["supported"] for rule in result["rules"] if rule["handle"] == 18))
        definition["flags"].remove("timeout")
        call = next(entry["rule"] for entry in entries if entry.get("rule", {}).get("handle") == 17)
        call["expr"][0] = match("ip", "saddr", prefix("203.0.113.0", 24))
        result = self.run_review(source, REVIEW_POLICY)
        self.assertEqual(len(result["findings"]), 4)
        self.assertEqual(next(rule["review_sources"] for rule in result["rules"] if rule["handle"] == 18), [])

    def test_model_priority_trace_preserves_only_validated_output(self):
        class Model:
            label = "Test model"
            model = "fixture"

            def __call__(self, evidence, available):
                if "policy" in available:
                    return {"action": "policy"}
                candidate = evidence["review_candidates"][0]
                return {"action": "finish", "priority": {
                    "finding_id": candidate["finding_id"], "reason": candidate["reasons"][0],
                }}

        report = self.run_review(review_snapshot(), REVIEW_POLICY, Model())
        self.assertEqual(report["model_name"], "fixture")
        self.assertEqual(report["model_trace"][0]["response"], {"action": "policy"})
        self.assertIn("available", report["model_trace"][0]["input"])
        self.assertEqual(report["model_trace"][-1]["response"]["priority"]["finding_id"],
                         report["model_priority"]["finding_id"])

    def test_unsupported_model_choice_is_withheld_from_report_and_log(self):
        def model(evidence, available):
            if "policy" in available:
                return {"action": "policy"}
            candidate = evidence["review_candidates"][0]
            return {"action": "finish", "priority": {
                "finding_id": candidate["finding_id"], "reason": "local_listener",
            }}

        model.label = "Test model"
        source = review_snapshot()
        rule = next(entry["rule"] for entry in source["ruleset"]["nftables"] if "rule" in entry)
        rule["comment"] = "private rule comment"
        with TemporaryDirectory() as directory:
            log = Path(directory) / "audit.jsonl"
            report = audit(source, load_policy(REVIEW_POLICY), model, log)
            self.assertEqual(len(report["findings"]), 5)
            self.assertIsNone(report["model_priority"])
            self.assertIsNone(report["model_trace"][-1]["response"])
            self.assertIn("Rejected a priority", report["status"])
            self.assertNotIn("private rule comment", json.dumps(report))
            self.assertNotIn("review_candidates", log.read_text())
            self.assertNotIn("Ollama suggests reviewing", report_html(report))
