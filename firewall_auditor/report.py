"""HTML for the firewall inventory and audit report."""
from collections import defaultdict
from html import escape
import json


VERDICTS = {
    "accept": "Allow", "drop": "Drop", "reject": "Reject", "jump": "Jump",
    "goto": "Go to", "return": "Return", "other": "Review",
}


def esc(value):
    return escape(str(value), quote=True)


def _json_details(value):
    return "<pre><code>" + esc(json.dumps(value, indent=2)) + "</code></pre>"


def _scope(sources):
    labels = {"0.0.0.0/0": "Any IPv4", "::/0": "Any IPv6"}
    return ", ".join(labels.get(source, source) for source in sources) or "No matching sources"


def _service(port):
    return f"TCP {port}" if port else "Any protocol and port"


def _link(rule_id):
    return f'<a href="#rule-{esc(rule_id)}">{esc(rule_id)}</a>'


def _rule_table(rules):
    if not rules:
        return "<p>No rules in this chain.</p>"
    rows = []
    for rule in rules:
        service = _service(rule["port"])
        sources = _scope(rule["sources"])
        status = ""
        if not rule["supported"]:
            service = f'TCP {rule["port"]} (partial match)' if rule["port"] else "See rule details"
            sources, status = "See rule details", "<small>Manual review</small>"
        verdict = VERDICTS[rule["action"]]
        if rule.get("target"):
            verdict += f' to {rule["target"]}'
        handle = rule["handle"]
        handle = f'<small>Handle {esc(handle)}</small>' if handle is not None else ""
        rows.append(
            f'<tr id="rule-{esc(rule["id"])}" tabindex="-1"><th scope="row">{esc(rule["id"])}{handle}</th>'
            f'<td>{esc(verdict)}{status}</td><td>{esc(service)}</td><td>{esc(sources)}</td></tr>'
        )
        if "details" in rule:
            sets = ", ".join(rule["sets"])
            set_details = f'<p>Source set <code>{esc(sets)}</code></p>' if sets else ""
            expressions = esc("\n".join(json.dumps(expr) for expr in rule["details"]))
            rows.append(
                '<tr class="rule-detail"><td colspan="4"><details>'
                f'<summary>Captured rule <span class="muted">{esc(rule["id"])}</span></summary>'
                f'{set_details}<pre><code>{expressions}</code></pre></details></td></tr>'
            )
    return (
        '<div class="scroll"><table><thead><tr><th scope="col">Rule</th><th scope="col">Action</th>'
        '<th scope="col">Service</th><th scope="col">Sources</th>'
        '</tr></thead><tbody>' + "".join(rows) + '</tbody></table></div>'
    )


def configuration(chains, rules, gaps, captured=None, action=""):
    by_chain, tables = defaultdict(list), defaultdict(list)
    for rule in rules:
        by_chain[rule["chain"]].append(rule)
    for chain in chains:
        tables[(chain["family"], chain["table"])].append(chain)
    groups = []
    for (family, table), table_chains in tables.items():
        groups.append(f'<h3><code>{esc(family)} {esc(table)}</code></h3>')
        for chain in table_chains:
            policy = chain["policy"]
            path = (f'Input chain · Default {VERDICTS.get(policy, policy).lower()}'
                    if policy else "Called chain")
            if chain["priority"] is not None:
                path += f' · Priority {chain["priority"]}'
            if chain["dormant"]:
                path += " · Table inactive"
            groups.append(f'<h4><code>{esc(chain["chain"])}</code></h4><p class="muted">{esc(path)}</p>')
            groups.append(_rule_table(by_chain[chain["name"]]))
    if by_chain["UFW enrolled input"]:
        groups.append("<h3>Enrolled UFW rules</h3><p>Read separately by the change helper.</p>")
        groups.append(_rule_table(by_chain["UFW enrolled input"]))
    timestamp = ""
    if captured:
        capture_label = captured.replace("T", " ").replace("+00:00", " UTC")
        timestamp = f'<p class="muted">Captured <time datetime="{esc(captured)}">{esc(capture_label)}</time></p>'
    notes = "".join(f'<li>{esc(note)}</li>' for note in gaps)
    return ('<section aria-labelledby="configuration"><div class="section-title">'
            '<h2 id="configuration">Current firewall configuration</h2>' + action + '</div>'
            + timestamp + "".join(groups) + f'<ul class="muted">{notes}</ul></section>')


def _findings(result):
    cards = []
    priority = result["model_priority"]
    if priority:
        cards.append(f'<p><strong>Ollama suggests reviewing {_link(priority["finding_id"])} first.</strong> '
                     f'{esc(priority["explanation"])}</p>')
    for finding in result["findings"]:
        rule = finding["rule"]
        reference = _link(rule["id"])
        if finding["via"]:
            reference += " via " + _link(finding["via"])
        if finding["sets"]:
            reference += f' using <code>{esc(", ".join(finding["sets"]))}</code>'
        service = _service(finding["port"])
        expected = finding["expected"]
        if expected is None:
            expected_text = ("Confirm which services and sources should be allowed." if finding["port"] is None
                             else "No expected access policy for this service.")
        else:
            expected_text = _scope(expected) if expected else "The policy lists no allowed sources for this address family."
        severity = "high" if finding["severity"] == "High" else "muted"
        cards.append(
            f'<article><h3>{esc(finding["title"])}</h3>'
            f'<p><span class="{severity}">{esc(finding["severity"])}</span> · {reference}</p>'
            f'<dl><dt>Configured access</dt><dd>{esc(service)} from {esc(_scope(finding["sources"]))}</dd>'
            f'<dt>Expected access</dt><dd>{esc(expected_text)}</dd></dl>'
            f'<p>{esc(finding["why"])}</p>'
            f'<p class="muted">{esc(finding["listener"])} End-to-end reachability is unverified.</p>'
            f'<p><a href="#change-{esc(rule["id"])}">Review suggested change</a></p></article>'
        )
    if not result["findings"]:
        cards.append("<p>No issues found in the supported rules. Check the coverage notes above.</p>")
    count = len(result["findings"])
    return ('<section><h2 id="findings" tabindex="-1">Rules to review</h2>'
            f'<p class="muted">{count} {"finding" if count == 1 else "findings"} · '
            f'Audit {esc(result["audit_id"])}</p>' + "".join(cards) + '</section>')


def _model_report(result):
    if not result["model_trace"]:
        body = "<p>Ollama was disabled. The rule engine reviewed the snapshot and generated the changes.</p>"
    else:
        name = result["model_name"] or result["mode"]
        body = (f'<p><strong>{esc(name)}</strong> · {esc(result["status"])}</p>'
                '<p>The rule engine checks the firewall and generates the changes. '
                'The model can request evidence and suggest what to review first.</p>')
        for index, request in enumerate(result["model_trace"], 1):
            response = (_json_details(request["response"]) if request["response"] is not None
                        else "<p>No validated response.</p>")
            body += (f'<details><summary>Request {index} · {esc(request["outcome"])}</summary>'
                     '<h3>Audit data sent</h3>' + _json_details(request["input"]) +
                     '<h3>Validated response</h3>' + response + '</details>')
    return '<section><h2>What Ollama did</h2>' + body + '</section>'


def _changes(result, enrolled, rerun, refresh_on_request):
    cards = []
    for finding in result["findings"]:
        rule_id = finding["id"]
        steps = "".join(f'<li>{esc(step)}</li>' for step in finding["steps"])
        fragments = "".join(f'<li><code>{esc(line)}</code></li>' for line in finding["proposed"])
        proposal = f'<p>Draft rule fragments</p><ul>{fragments}</ul>' if fragments else ""
        proposed = (_scope(finding["suggested_sources"]) if finding["suggested_sources"]
                    else finding["advice"])
        cards.append(
            f'<article id="change-{esc(rule_id)}" tabindex="-1"><h3>Change for {_link(rule_id)}</h3>'
            f'<dl><dt>Current source scope</dt><dd>{esc(_scope(finding["sources"]))}</dd>'
            f'<dt>Suggested by the rule engine</dt><dd>{esc(proposed)}</dd></dl>'
            f'<details><summary>Manual change and verification steps</summary>{proposal}'
            f'<ol>{steps}</ol></details></article>'
        )
    if not cards:
        cards.append("<p>No changes suggested for this snapshot.</p>")
    else:
        cards.insert(0, "<p>Confirm who needs access, then make the change in your firewall manager.</p>")
    refresh = ("Run the audit again to capture the active firewall. Check the capture time above."
               if refresh_on_request else
               "For a live firewall, allow about 30 seconds for the collector to refresh "
               "before you run the audit again. Check the capture time above.")
    return ('<section><h2>What to change</h2>' + "".join(cards) + enrolled +
            f'<p class="muted">{refresh}</p>' + rerun + '</section>')


def report_html(result, enrolled="", rerun="", *, refresh_on_request=False):
    skip = '<a href="#findings">Skip to findings</a>'
    return (configuration(result["chains"], result["rules"], result["gaps"], result["captured_at"], skip)
            + _findings(result) + _model_report(result) + _changes(result, enrolled, rerun, refresh_on_request))
