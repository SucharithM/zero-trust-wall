"""Adapters for explicitly enrolled, administrator-owned test rules."""
import ipaddress
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys

from .remediation import atomic_write


def command(*args, data=None):
    try:
        result = subprocess.run(args, input=data, text=True, capture_output=True, check=True,
                                timeout=8, env={**os.environ, "LC_ALL": "C"})
    except subprocess.CalledProcessError as error:
        print(f"{Path(args[0]).name}: {error.stderr[:500].strip()}", file=sys.stderr)
        raise ValueError(f"Firewall manager failed: {Path(args[0]).name}.") from error
    except (subprocess.SubprocessError, OSError) as error:
        raise ValueError(f"Firewall manager failed: {Path(args[0]).name}.") from error
    if len(result.stdout) > 2 * 1024 * 1024:
        raise ValueError("Firewall response exceeded the size limit.")
    return result.stdout


class Nftables:
    table = "firewall_auditor"
    chain = "trial_input"
    executable = "/usr/sbin/nft"

    def __init__(self, ports, saved, runner=command):
        self.ports = set(ports)
        self.saved = Path(saved)
        self.run = runner

    @staticmethod
    def _match(protocol, field, value):
        return {"match": {"op": "==", "left": {"payload": {"protocol": protocol, "field": field}},
                          "right": value}}

    def _allow(self, port, source):
        network = ipaddress.IPv4Network(source)
        prefix = (str(network.network_address) if network.prefixlen == 32
                  else {"prefix": {"addr": str(network.network_address), "len": network.prefixlen}})
        # An IPv4 wildcard in this IPv4-only table needs no explicit address match.
        source_match = [self._match("ip", "saddr", prefix)] if network.prefixlen else []
        return [*source_match, self._match("tcp", "dport", port), {"accept": None}]

    def _active(self):
        data = json.loads(self.run(self.executable, "-j", "-n", "-a", "list", "table", "ip", self.table))
        entries = data["nftables"]
        chains = [entry["chain"] for entry in entries if "chain" in entry]
        if len(chains) != 1 or any(set(entry) - {"metainfo", "table", "chain", "rule"}
                                   for entry in entries):
            raise ValueError("The managed nftables table changed.")
        chain = chains[0]
        required = {"family": "ip", "table": self.table, "name": self.chain, "hook": "input",
                    "type": "filter", "prio": 0, "policy": "accept"}
        if any(chain.get(key) != value for key, value in required.items()):
            raise ValueError("The managed nftables chain changed.")
        rules = [entry["rule"] for entry in entries if "rule" in entry]
        if len(rules) != len(self.ports) * 2:
            raise ValueError("The managed nftables rule count changed.")
        result = {}
        for index, port in enumerate(sorted(self.ports)):
            rule, deny = rules[index * 2:index * 2 + 2]
            if any(item.get("family") != "ip" or item.get("table") != self.table
                   or item.get("chain") != self.chain for item in (rule, deny)):
                raise ValueError("Unexpected managed firewall rule.")
            port_match = self._match("tcp", "dport", port)
            if deny["expr"] != [port_match, {"drop": None}]:
                raise ValueError("The managed deny rule changed.")
            expr = rule["expr"]
            if expr == [port_match, {"accept": None}]:
                source = "0.0.0.0/0"
            elif len(expr) == 3 and expr[1:] == [port_match, {"accept": None}]:
                value = expr[0]["match"]["right"]
                if isinstance(value, dict):
                    prefix = value["prefix"]
                    value = f"{prefix['addr']}/{prefix['len']}"
                source = str(ipaddress.IPv4Network(value))
                if expr[0] != self._match("ip", "saddr", expr[0]["match"]["right"]):
                    raise ValueError("The managed IPv4 match changed.")
            else:
                raise ValueError("The managed allow rule changed.")
            if type(rule.get("handle")) is not int:
                raise ValueError("The managed nftables rule has no handle.")
            result[port] = (source, rule["handle"])
        return result

    def read(self):
        return {port: value[0] for port, value in self._active().items()}

    def references(self):
        return {port: f"ip {self.table} / {self.chain} · handle {value[1]}"
                for port, value in self._active().items()}

    def replace(self, port, before, after):
        current, handle = self._active()[port]
        if current != before:
            raise ValueError("The nftables rule changed before the update.")
        rule = {"family": "ip", "table": self.table, "chain": self.chain, "handle": handle,
                "expr": self._allow(port, after)}
        self.run(self.executable, "-j", "-f", "-", data=json.dumps({"nftables": [{"replace": {"rule": rule}}]}))

    def _render(self, rules):
        lines = [f"table ip {self.table} {{", f" chain {self.chain} {{",
                 "  type filter hook input priority 0; policy accept;"]
        for port, source in sorted(rules.items()):
            text = "" if source == "0.0.0.0/0" else f"ip saddr {source} "
            lines.extend([f"  {text}tcp dport {port} accept", f"  tcp dport {port} drop"])
        return "\n".join([*lines, " }", "}", ""])

    def read_saved(self):
        content = self.saved.read_text()
        result = {}
        for line in content.splitlines():
            match = re.fullmatch(r"  (?:ip saddr ([0-9./]+) )?tcp dport (\d+) accept", line)
            if match:
                result[int(match[2])] = str(ipaddress.IPv4Network(match[1] or "0.0.0.0/0"))
        if set(result) != self.ports or content != self._render(result):
            raise ValueError("The saved nftables file changed outside the auditor.")
        return result

    def save(self, rules, expected):
        if self.read_saved() != expected:
            raise ValueError("Saved nftables configuration changed during approval.")
        atomic_write(self.saved, self._render(rules))

    def provision(self, rules):
        if self.saved.exists():
            raise ValueError("The managed startup file already exists.")
        data = self._render(rules)
        self.run(self.executable, "-c", "-f", "-", data=data)
        atomic_write(self.saved, data)


class Ufw:
    executable = "/usr/sbin/ufw"
    requires_persistence = True

    def __init__(self, ports, runner=command):
        self.ports = set(ports)
        self.run = runner

    def _marked(self):
        text = self.run(self.executable, "status", "numbered")
        if not text.startswith("Status: active"):
            raise ValueError("UFW must already be active.")
        result = {port: [] for port in self.ports}
        for line in text.splitlines():
            marker = re.search(r"# firewall-auditor-(\d+)\s*$", line)
            if not marker:
                continue
            match = re.fullmatch(
                r"\[\s*(\d+)\]\s+(\d+)/tcp\s+ALLOW IN\s+([0-9./]+)"
                r"\s+# firewall-auditor-(\d+)\s*", line,
            )
            port = int(marker[1])
            if not match or int(match[2]) != port or port not in result:
                raise ValueError("Unsupported or ambiguous enrolled UFW rule.")
            result[port].append((str(ipaddress.IPv4Network(match[3])), int(match[1])))
        return result

    def _active(self):
        result = self._marked()
        if any(len(entries) != 1 for entries in result.values()):
            raise ValueError("Each enrolled UFW rule must have one matching marker.")
        return {port: entries[0] for port, entries in result.items()}

    def read(self):
        return {port: entry[0] for port, entry in self._active().items()}

    def references(self):
        return {port: f"UFW rule {entry[1]} · firewall-auditor-{port}"
                for port, entry in self._active().items()}

    def replace(self, port, before, after):
        current, index = self._active()[port]
        if current != before:
            raise ValueError("UFW rule changed before approval.")
        # Insert adjacent so the replacement retains the original priority after removal.
        self.run(self.executable, "insert", str(index), "allow", "in", "proto", "tcp",
                 "from", after, "to", "any", "port", str(port), "comment", f"firewall-auditor-{port}")
        self._remove_adjacent(port, before, after, undo=False)

    def _remove_adjacent(self, port, before, after, *, undo):
        entries = self._marked()[port]
        if len(entries) != 2 or entries != [(after, entries[0][1]), (before, entries[0][1] + 1)]:
            raise ValueError("UFW replacement changed unexpectedly.")
        self.run(self.executable, "--force", "delete", str(entries[0 if undo else 1][1]))

    def restore_transient(self, port, before, after):
        if len(self._marked()[port]) == 2:
            self._remove_adjacent(port, before, after, undo=True)

    def read_saved(self):
        result = {}
        for line in self.run(self.executable, "show", "added").splitlines():
            if not line.startswith("ufw allow "):
                continue
            tokens = shlex.split(line)
            if "comment" not in tokens:
                continue
            marker = re.fullmatch(r"firewall-auditor-(\d+)", tokens[-1])
            if not marker:
                continue
            port = int(marker[1])
            fields = tokens[3:] if tokens[2] == "in" else tokens[2:]
            if len(fields) != 10 or len(set(fields[::2])) != 5:
                raise ValueError("Unsupported saved UFW rule.")
            values = dict(zip(fields[::2], fields[1::2]))
            if (port not in self.ports or port in result or values.get("proto") != "tcp"
                    or values.get("port") != str(port) or values.get("to") != "any"):
                raise ValueError("Unexpected saved UFW rule.")
            result[port] = str(ipaddress.IPv4Network(values["from"]))
        if set(result) != self.ports:
            raise ValueError("Could not confirm all saved UFW rules.")
        return result

    def save(self, rules, expected):
        if self.read() != rules or self.read_saved() != rules:
            raise ValueError("UFW saved policy could not be confirmed.")
