import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from firewall_auditor.backends import Nftables, Ufw


class BackendTests(unittest.TestCase):
    def test_nft_replacement_preserves_handle_and_deny(self):
        calls = []
        def run(*args, data=None):
            calls.append((args, data))
            if data:
                return ""
            return json.dumps({"nftables": entries})

        port = 18081
        with TemporaryDirectory() as tmp:
            backend = Nftables([port], Path(tmp) / "managed.nft", run)
            scope = {"family": "ip", "table": backend.table}
            entries = [
                {"table": {**scope, "name": backend.table}},
                {"chain": {**scope, "name": backend.chain, "type": "filter", "hook": "input",
                           "prio": 0, "policy": "accept"}},
                {"rule": {**scope, "chain": backend.chain, "handle": 7,
                          "expr": backend._allow(port, "192.0.2.0/24")}},
                {"rule": {**scope, "chain": backend.chain, "handle": 8,
                          "expr": [backend._match("tcp", "dport", port), {"drop": None}]}},
            ]
            backend.provision({port: "192.0.2.0/24"})
            backend.replace(port, "192.0.2.0/24", "192.0.2.10/32")
            replace = json.loads(calls[-1][1])["nftables"][0]["replace"]["rule"]
            self.assertEqual(replace["handle"], 7)
            self.assertNotIn("drop", calls[-1][1])
            backend.save({port: "192.0.2.10/32"}, {port: "192.0.2.0/24"})
            self.assertEqual(backend.read_saved(), {port: "192.0.2.10/32"})
            with self.assertRaises(ValueError):
                backend.replace(port, "198.51.100.0/24", "192.0.2.10/32")

    def test_ufw_recovers_only_the_expected_adjacent_provisional_rule(self):
        calls = []
        def run(*args):
            calls.append(args)
            return ("Status: active\n"
                    "[ 3] 18081/tcp                  ALLOW IN    192.0.2.10 # firewall-auditor-18081\n"
                    "[ 4] 18081/tcp                  ALLOW IN    192.0.2.0/24 # firewall-auditor-18081\n")
        backend = Ufw([18081], run)
        backend.restore_transient(18081, "192.0.2.0/24", "192.0.2.10/32")
        self.assertEqual(calls[-1][-2:], ("delete", "3"))
        with self.assertRaises(ValueError):
            backend.restore_transient(18081, "192.0.2.0/24", "192.0.2.50/32")

    def test_ufw_reads_configured_rules_through_its_manager(self):
        backend = Ufw([18081], lambda *_: (
            "Added user rules (see 'ufw status' for running firewall):\n"
            "ufw allow from 192.0.2.10 to any port 18081 proto tcp comment 'firewall-auditor-18081'\n"
        ))
        self.assertEqual(backend.read_saved(), {18081: "192.0.2.10/32"})
