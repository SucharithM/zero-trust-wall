"""Read-only review of a conservative subset of nftables JSON rules."""
from collections import defaultdict
from datetime import datetime, timezone
import ipaddress
import json
from pathlib import Path
import time


MAX_SNAPSHOT = 2 * 1024 * 1024
SENSITIVE = {22: "SSH", 3389: "RDP", 3306: "MySQL", 5432: "PostgreSQL",
             1433: "SQL Server", 6379: "Redis", 27017: "MongoDB"}
ANY = {4: "0.0.0.0/0", 6: "::/0"}
FAMILIES = {"ip": (4,), "ip6": (6,), "inet": (4, 6)}
MAX_SET_MEMBERS = 256


def read_json(path, limit=MAX_SNAPSHOT):
    with Path(path).open("rb") as file:
        data = file.read(limit + 1)
    if len(data) > limit:
        raise ValueError("JSON input exceeds the size limit.")
    return json.loads(data)


def load_snapshot(path, max_age):
    snapshot = read_json(path)
    age = time.time() - snapshot["captured_at"]
    if not -5 <= age <= max_age:
        raise ValueError("Firewall snapshot is stale. Check the collector.")
    return snapshot


def captured_at(snapshot):
    return datetime.fromtimestamp(snapshot["captured_at"], timezone.utc).isoformat(timespec="seconds")


def _chain_key(item, name_field):
    return tuple(str(item[field]) for field in ("family", "table", name_field))


def _network(value, version):
    if isinstance(value, dict):
        prefix = value["prefix"]
        value = f"{prefix['addr']}/{prefix['len']}"
    if not isinstance(value, str):
        raise ValueError("Expected an address or CIDR.")
    network = ipaddress.ip_network(value, strict=False)
    if network.version != version:
        raise ValueError("Address family mismatch.")
    return network


def _source_scope(value, version, table, sets):
    reference = None
    if isinstance(value, str) and value.startswith("@"):
        reference = value
        definition = sets[(*table, value[1:])]
        expected_type = {4: "ipv4_addr", 6: "ipv6_addr"}[version]
        if (definition["type"] != expected_type or
                set(definition.get("flags", [])) - {"constant", "interval"} or
                "timeout" in definition):
            raise ValueError("Set membership requires manual review.")
        members = definition.get("elem", [])
    elif isinstance(value, dict) and "set" in value:
        members = value["set"]
    else:
        members = value
    if not isinstance(members, list):
        members = [members]
    if len(members) > MAX_SET_MEMBERS:
        raise ValueError("Source set exceeds the review limit.")
    networks = []
    for member in members:
        if isinstance(member, dict) and "elem" in member:
            element = member["elem"]
            if set(element) - {"val", "comment"}:
                raise ValueError("Dynamic set membership requires manual review.")
            member = element["val"]
        if isinstance(member, dict) and "range" in member:
            first, last = (_network(address, version) for address in member["range"])
            if first.num_addresses != 1 or last.num_addresses != 1:
                raise ValueError("Expected individual addresses in range endpoints.")
            networks.extend(ipaddress.summarize_address_range(first.network_address, last.network_address))
        else:
            networks.append(_network(member, version))
        if len(networks) > MAX_SET_MEMBERS:
            raise ValueError("Expanded source set exceeds the review limit.")
    return [str(net) for net in ipaddress.collapse_addresses(networks)], reference


def _rule_details(exprs):
    if isinstance(exprs, list):
        return [_rule_details(value) for value in exprs]
    if not isinstance(exprs, dict):
        return exprs
    return {key: (None if key in {"log", "counter"} and isinstance(value, dict) else _rule_details(value))
            for key, value in exprs.items() if key != "comment"}


def _rule(item, chain, sets):
    versions = FAMILIES[chain[0]]
    sources = port = target = None
    references = []
    action = "other"
    supported = True
    exprs = item["expr"]
    for index, expr in enumerate(exprs):
        if len(expr) != 1:
            supported = False
            continue
        key, value = next(iter(expr.items()))
        if key in {"accept", "drop", "reject", "return", "jump", "goto"} and index == len(exprs) - 1:
            action = key
            if key in {"jump", "goto"}:
                target = value.get("target") if isinstance(value, dict) else None
                supported &= isinstance(target, str) and key == "jump"
        elif key == "counter":
            continue
        elif key == "match" and isinstance(value, dict) and value.get("op") in {"==", "in"}:
            left = value.get("left")
            payload = left.get("payload", {}) if isinstance(left, dict) else {}
            right = value.get("right")
            if payload == {"protocol": "tcp", "field": "dport"} and port is None:
                if value["op"] == "==" and type(right) is int and 1 <= right <= 65535:
                    port = right
                else:
                    supported = False
            elif payload in ({"protocol": "ip", "field": "saddr"},
                             {"protocol": "ip6", "field": "saddr"}) and sources is None:
                try:
                    version = 4 if payload["protocol"] == "ip" else 6
                    if version not in versions:
                        raise ValueError("Address family mismatch.")
                    sources, reference = _source_scope(right, version, chain[:2], sets)
                    if reference:
                        references.append(reference)
                except (ValueError, KeyError, TypeError):
                    supported = False
            else:
                supported = False
        else:
            supported = False
    return {
        "chain": " / ".join(chain), "handle": item.get("handle"), "action": action,
        "port": port, "sources": [ANY[version] for version in versions] if sources is None else sources,
        "supported": supported and action != "other", "target": target,
        "sets": references, "details": _rule_details(exprs),
    }


def _intersection(left, right):
    result = set()
    for first in left:
        for second in right:
            if first.version == second.version and first.overlaps(second):
                result.add(max(first, second, key=lambda net: net.prefixlen))
    return sorted(result, key=lambda net: (net.version, net.network_address, net.prefixlen))


def normalize(ruleset):
    """Display input chains and their immediate call targets in snapshot order."""
    if not isinstance(ruleset["nftables"], list):
        raise ValueError("Expected an nftables JSON ruleset.")
    entries = ruleset["nftables"]
    chains, sets, table_flags = {}, {}, {}
    entries_by_chain = defaultdict(list)
    for entry in entries:
        if "chain" in entry:
            chain = entry["chain"]
            if chain["family"] in FAMILIES:
                chains[_chain_key(chain, "name")] = chain
        elif "table" in entry:
            table = entry["table"]
            table_flags[(table["family"], table["name"])] = table.get("flags", [])
        elif "set" in entry:
            definition = entry["set"]
            sets[_chain_key(definition, "name")] = definition
    base = {key for key, chain in chains.items() if chain.get("hook") == "input"}
    calls = defaultdict(list)
    for entry in entries:
        if "rule" not in entry:
            continue
        item = entry["rule"]
        chain = _chain_key(item, "chain")
        if chain in chains:
            entries_by_chain[chain].append(item)
            for expression in item["expr"]:
                for action in ("jump", "goto"):
                    target = expression.get(action)
                    if isinstance(target, dict) and isinstance(target.get("target"), str):
                        calls[(*chain[:2], target["target"])].append((chain, item))
    children = {target for target, paths in calls.items()
                if target in chains and not chains[target].get("hook")
                and any(parent in base for parent, _ in paths)}
    visible = base | children
    if sum(len(entries_by_chain[key]) for key in visible) > 500:
        raise ValueError("More than 500 inbound rules. Review the snapshot manually.")
    rules, by_chain, by_item = [], defaultdict(list), {}
    for key in chains:
        if key not in visible:
            continue
        for item in entries_by_chain[key]:
            rule = {"id": f"R{len(rules) + 1}", **_rule(item, key, sets)}
            rules.append(rule)
            by_chain[key].append(rule)
            by_item[id(item)] = rule
    gaps = ["This review checks configured rules, not effective packet flow."]
    if not base:
        gaps.append("No supported input base chain was found. Review the host firewall setup.")
    if len(base) > 1:
        gaps.append("Several input base chains exist. Review their priorities and combined behavior.")
    for key in visible:
        chains[key] = {**chains[key], "dormant": "dormant" in table_flags.get(key[:2], [])}
    for key, chain_rules in by_chain.items():
        for rule in chain_rules:
            if chains[key]["dormant"] or (key in base and chains[key].get("type", "filter") != "filter"):
                rule["supported"] = False
            if rule["target"] and (*key[:2], rule["target"]) not in children:
                rule["supported"] = False
    for key in children:
        paths = calls[key]
        parent = by_item.get(id(paths[0][1])) if len(paths) == 1 and paths[0][0] in base else None
        for rule in by_chain[key]:
            if not parent or not parent["supported"] or parent["action"] != "jump" or rule["target"]:
                rule["supported"] = False
                continue
            rule["via"] = parent["id"]
            rule["review_sets"] = list(dict.fromkeys(parent["sets"] + rule["sets"]))
            rule["review_port"] = rule["port"] or parent["port"]
            scope = _intersection(map(ipaddress.ip_network, rule["sources"]),
                                  list(map(ipaddress.ip_network, parent["sources"])))
            if parent["port"] and rule["port"] and parent["port"] != rule["port"]:
                scope = []
            rule["review_sources"] = [str(net) for net in scope]
    if any(not rule["supported"] for rule in rules):
        gaps.append("Rules marked Manual review have unsupported matches, verdicts or input paths.")
    return [{"name": " / ".join(key), "family": key[0], "table": key[1], "chain": key[2],
             "policy": chain.get("policy", "accept") if key in base else None,
             "priority": chain.get("prio"), "dormant": chain["dormant"]}
            for key, chain in chains.items() if key in visible], rules, gaps


def load_policy(raw):
    policy = {}
    for key, item in raw.items():
        port = int(key)
        if not 1 <= port <= 65535 or port in policy or not isinstance(item["sources"], list):
            raise ValueError("Invalid service policy.")
        networks = [ipaddress.ip_network(source) for source in item["sources"]]
        policy[port] = {
            "name": str(item["name"])[:100],
            "sources": {version: list(ipaddress.collapse_addresses(
                net for net in networks if net.version == version)) for version in (4, 6)},
        }
    return policy


def findings(rules, policy, listeners):
    result = []
    for rule in rules:
        if not rule["supported"] or rule["action"] != "accept":
            continue
        port = rule.get("review_port", rule["port"])
        sources = rule.get("review_sources", rule["sources"])
        if not sources:
            continue
        scope = [ipaddress.ip_network(source) for source in sources]
        unrestricted = any(network.prefixlen == 0 for network in scope)
        service = policy.get(port)
        expected = None
        permitted = []
        reasons = []
        if port is None and unrestricted:
            severity, title = "High", "Unrestricted inbound accept rule"
            reasons.append("blanket_accept")
            why = "The rule allows unmatched services and ports, including services added later."
            advice = "Replace the blanket accept with specific service and source rules."
        elif port is None:
            continue
        elif service is not None:
            expected = [net for version in sorted({net.version for net in scope})
                        for net in service["sources"][version]]
            if all(any(network.subnet_of(allowed) for allowed in service["sources"][network.version])
                   for network in scope):
                continue
            severity = "High" if port in SENSITIVE and unrestricted else "Medium"
            title = f"{service['name']} allows sources outside policy"
            reasons.append("policy_mismatch")
            why = "Clients outside the configured policy match this allow rule."
            permitted = [str(net) for net in _intersection(scope, expected)]
            advice = ("Limit this rule to " + ", ".join(permitted) + "." if permitted else
                      "Confirm this service is unused by these sources before removing the allow.")
        elif unrestricted:
            severity = "High" if port in SENSITIVE else "Review"
            title = f"{SENSITIVE.get(port, f'TCP {port}')} accepts any source"
            reasons.append("policy_missing")
            why = "Any source can match this rule. Add an expected access policy to check the intended scope."
            advice = "Confirm which clients need this service and restrict the rule to their networks if appropriate."
        else:
            continue
        if port in SENSITIVE and unrestricted:
            reasons.append("sensitive_service")
        if port is None:
            listener_evidence = "This rule has no destination port constraint."
        elif listeners is None:
            listener_evidence = "Listening sockets were not inspected."
        elif port in listeners:
            listener_evidence = f"A local TCP listener was observed on port {port}."
            reasons.append("local_listener")
        else:
            listener_evidence = f"No local TCP listener was observed on port {port}."
        locate = f"Locate {rule['id']} in {rule['chain']}"
        if type(rule["handle"]) is int:
            locate += f" (handle {rule['handle']})"
        proposed = [
            f"{'ip' if ipaddress.ip_network(source).version == 4 else 'ip6'} "
            f"saddr {source} tcp dport {port} accept"
            for source in permitted
        ]
        result.append({
            "id": rule["id"], "severity": severity, "title": title, "rule": rule,
            "sources": sources, "port": port, "expected": None if expected is None else list(map(str, expected)),
            "suggested_sources": permitted, "why": why, "reasons": reasons,
            "via": rule.get("via"), "sets": rule.get("review_sets", rule.get("sets", [])),
            "listener": listener_evidence, "advice": advice, "proposed": proposed,
            "steps": [
                locate + ". Confirm required clients and any management access.",
                "Back up the ruleset and arrange console access before drafting the change.",
                advice + " Draft the change in the firewall's managed configuration, preserve rule order, and have an operator validate the draft before applying it.",
                "Verify that required clients retain access and other clients lose it. Restore the backup if required traffic breaks.",
            ],
        })
    return sorted(result, key=lambda finding: {"High": 0, "Medium": 1, "Review": 2}[finding["severity"]])
