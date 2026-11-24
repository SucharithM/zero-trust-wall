import unittest
from unittest.mock import patch

from deploy import collect


class CollectorTests(unittest.TestCase):
    def test_live_capture_runs_the_same_read_only_commands_each_time(self):
        rules = b'{"nftables":[]}'
        with patch.object(collect, "read_command", side_effect=[
            rules, b"LISTEN 0 128 127.0.0.1:8443 0.0.0.0:*",
            rules, b"",
        ]) as command:
            first = collect.capture(("/usr/bin/sudo", "-n", "/usr/sbin/nft"))
            second = collect.capture(("/usr/bin/sudo", "-n", "/usr/sbin/nft"))
        self.assertEqual(first["listeners"], [8443])
        self.assertEqual(second["listeners"], [])
        self.assertEqual(command.call_args_list[0].args,
                         ("/usr/bin/sudo", "-n", "/usr/sbin/nft", "-j", "-n", "-a", "list", "ruleset"))
        self.assertEqual(command.call_args_list[2], command.call_args_list[0])
