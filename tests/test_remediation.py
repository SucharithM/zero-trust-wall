import tempfile
import unittest
from pathlib import Path

from firewall_auditor.remediation import Coordinator


class Firewall:
    def __init__(self):
        self.rules = {8081: "192.0.2.0/24", 8082: "192.0.2.0/24"}
        self.saved = self.rules.copy()
        self.writes = []

    def read(self):
        return self.rules.copy()

    def replace(self, port, before, after):
        if self.rules[port] != before:
            raise ValueError("Rule changed")
        self.rules[port] = after
        self.writes.append((port, after))

    def read_saved(self):
        return self.saved.copy()

    def save(self, rules, expected):
        if self.saved != expected:
            raise ValueError("Saved policy changed")
        self.saved = rules.copy()


class RemediationTests(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.path = Path(folder.name)
        self.backend = Firewall()
        self.ok = True
        self.clock = 100
        self.make_coordinator()

    def make_coordinator(self, trial=False):
        self.app = Coordinator(self.backend, {8081: "192.0.2.8/32", 8082: "192.0.2.8/32"},
                               self.verify, self.path, trial=trial, now=lambda: self.clock)

    def verify(self, port, restricted):
        return {"required": True, "trial": not restricted or (not self.ok and port == 8082)}

    def test_approval_applies_in_order_and_persists_exact_batch(self):
        review = self.app.prepare("owner", [8082, 8081], True)
        self.assertFalse(self.backend.writes)
        with self.assertRaises(ValueError):
            self.app.apply("someone else", review["id"])
        result = self.app.apply("owner", review["id"])
        self.assertEqual(result["status"], "saved")
        self.assertEqual([p for p, _ in self.backend.writes], [8082, 8081])
        self.assertEqual(self.backend.saved, self.backend.rules)
        with self.assertRaises(ValueError):
            self.app.apply("owner", review["id"])

    def test_second_failure_rolls_back_in_reverse_order(self):
        before = self.backend.read()
        self.ok = False
        review = self.app.prepare("owner", [8081, 8082], True)
        result = self.app.apply("owner", review["id"])
        self.assertEqual(result["status"], "rolled_back")
        self.assertEqual([p for p, _ in self.backend.writes], [8081, 8082, 8082, 8081])
        self.assertEqual(self.backend.saved, before)
        self.assertEqual(self.backend.read(), before)

    def test_trial_recovers_after_restart_and_expiry(self):
        before = self.backend.read()
        self.make_coordinator(trial=True)
        review = self.app.prepare("reviewer", [8081, 8082], False)
        self.assertEqual(self.app.apply("reviewer", review["id"])["status"], "trial_verified")
        self.assertEqual(self.backend.saved, before)
        self.make_coordinator(trial=True)
        self.clock += 600
        self.app.recover()
        self.assertEqual(self.backend.read(), before)
        self.assertEqual(self.app.history("reviewer")[0]["status"], "trial_reset")

    def test_separate_personal_changes_survive_expiry_and_helper_restart(self):
        saved_before = self.backend.read_saved()
        for port in (8081, 8082):
            review = self.app.prepare("owner", [port], False)
            self.assertEqual(self.app.apply("owner", review["id"])["status"], "verified")
            self.clock += 600
            self.make_coordinator()
            self.app.recover()
            for completed in range(8081, port + 1):
                self.assertEqual(self.backend.read()[completed], "192.0.2.8/32")
        self.assertEqual(self.backend.read_saved(), saved_before)
        self.assertEqual(self.app.options(), [])

    def test_drift_rejects_before_any_write(self):
        review = self.app.prepare("owner", [8081], False)
        self.backend.rules[8081] = "192.0.2.0/25"
        with self.assertRaises(ValueError):
            self.app.apply("owner", review["id"])
        self.assertFalse(self.backend.writes)
