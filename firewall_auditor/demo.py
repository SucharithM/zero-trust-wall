"""Sanitized data for the HTTPS demo and tests."""
import time

POLICY = {
    "22": {"name": "SSH", "sources": ["192.0.2.8/32", "2001:db8:10::/64"]},
    "3306": {"name": "MySQL", "sources": ["198.51.100.14/32"]},
    "443": {"name": "HTTPS", "sources": ["0.0.0.0/0", "::/0"]},
}


def match(protocol, field, value):
    return {"match": {"op": "==", "left": {"payload": {"protocol": protocol, "field": field}},
                      "right": value}}


def snapshot():
    table = {"family": "inet", "table": "filter"}
    rules = [
        [match("tcp", "dport", 22), {"accept": None}],
        [match("tcp", "dport", 3306), {"accept": None}],
        [match("tcp", "dport", 443), {"accept": None}],
        [match("ip", "saddr", "198.51.100.14"), match("tcp", "dport", 3306), {"accept": None}],
        [match("ip6", "saddr", {"prefix": {"addr": "2001:db8:10::", "len": 64}}),
         match("tcp", "dport", 22), {"accept": None}],
    ]
    return {
        "captured_at": time.time(), "listeners": [22, 443, 3306],
        "ruleset": {"nftables": [
            {"chain": {**table, "name": "input", "type": "filter", "hook": "input", "policy": "drop"}},
            *[{"rule": {**table, "chain": "input", "handle": index + 1,
                        "expr": expr}} for index, expr in enumerate(rules)],
        ]},
    }


REVIEW_POLICY = {
    **POLICY,
    "8080": {"name": "Internal web app", "sources": ["192.0.2.55/32"]},
    "8443": {"name": "Admin dashboard", "sources": ["2001:db8:10::/64"]},
    "9443": {"name": "Team dashboard", "sources": ["198.51.100.7/32"]},
}


def review_snapshot():
    """Five offline audit cases using documentation-only addresses."""
    table = {"family": "inet", "table": "office_filter"}

    def source(protocol, address, length):
        return match(protocol, "saddr", {"prefix": {"addr": address, "len": length}})

    def rule(handle, *expr, chain="input"):
        return {"rule": {**table, "chain": chain, "handle": handle, "expr": list(expr)}}

    accept = {"accept": None}
    return {"captured_at": time.time(), "listeners": [22, 443, 8080, 9443], "ruleset": {"nftables": [
        {"chain": {**table, "name": "input", "type": "filter", "hook": "input", "prio": 0, "policy": "drop"}},
        {"chain": {**table, "name": "team_services"}},
        {"set": {**table, "name": "team_clients", "type": "ipv4_addr", "flags": ["interval"],
                 "elem": [{"prefix": {"addr": "198.51.100.0", "len": 24}}]}},
        rule(11, match("tcp", "dport", 22), accept),
        rule(13, source("ip", "192.0.2.0", 24), match("tcp", "dport", 8080), accept),
        rule(14, match("ip6", "saddr", {"set": [
            {"prefix": {"addr": "2001:db8:10::", "len": 64}},
            {"prefix": {"addr": "2001:db8:20::", "len": 64}},
        ]}), match("tcp", "dport", 8443), accept),
        rule(15, match("tcp", "dport", 443), accept),
        rule(16, match("ip", "saddr", "198.51.100.14"), match("tcp", "dport", 3306), accept),
        rule(17, source("ip", "198.51.100.0", 25), {"jump": {"target": "team_services"}}),
        rule(12, accept),
        rule(18, match("ip", "saddr", "@team_clients"), match("tcp", "dport", 9443), accept,
             chain="team_services"),
    ]}}
