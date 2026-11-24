"""Serve the firewall review console over HTTPS."""
import argparse
import base64
import re
from functools import partial
from hmac import compare_digest, digest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import os
from secrets import token_urlsafe
import ssl
from threading import BoundedSemaphore, Lock
from urllib.parse import parse_qs

from .agent import Ollama, audit, ufw_evidence
from .core import captured_at, load_policy, load_snapshot, normalize, read_json
from .demo import REVIEW_POLICY, review_snapshot
from .helper import call_helper
from .report import configuration, esc, report_html


STYLE = """
:root{color-scheme:dark;--ink:#e6edf3;--muted:#a9b9ca;--line:#304259;--panel:#132134;
--accent:#94e6bc;--warn:#ffbc8c}*{box-sizing:border-box}
body{margin:0;background:#0b1422;color:var(--ink);font:16px/1.55 system-ui,sans-serif}
main{max-width:1050px;margin:auto;padding:56px 24px 72px}h1,h2,h3{line-height:1.2}
h1{font-size:clamp(2rem,5vw,3.2rem);letter-spacing:-.04em;margin:12px 0}
h2{font-size:1.45rem;margin:0 0 16px}h3{margin:10px 0}
p{margin:8px 0}a{color:var(--accent);text-underline-offset:3px}
.pill{color:var(--accent);border:1px solid var(--line);border-radius:20px;padding:4px 11px}
.muted,small{color:var(--muted)}.high,.error{color:var(--warn)}
section,article{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:20px;margin:20px 0}
button{background:var(--accent);color:#122b22;border:0;border-radius:7px;padding:11px 18px;
font:inherit;font-weight:700;cursor:pointer}button:focus-visible{outline:3px solid white;outline-offset:3px}
.scroll{overflow:auto}table{border-collapse:collapse;width:100%;text-align:left}
th,td{border-bottom:1px solid var(--line);padding:10px 12px;vertical-align:top}
th{color:var(--muted);font-weight:600}th small,td small{display:block}
ol,ul{padding-left:24px}li{margin:6px 0}
code{font-size:.92em;overflow-wrap:anywhere}h4{margin:16px 0 4px}
dt{font-weight:650}dd{margin:0 0 8px;overflow-wrap:anywhere}
summary{cursor:pointer}details+details{margin-top:8px}
pre{white-space:pre-wrap;overflow-wrap:anywhere;max-height:24rem;overflow:auto}
:target,a:focus-visible,summary:focus-visible{outline:2px solid var(--accent);outline-offset:2px}
form{margin-top:12px}td{overflow-wrap:anywhere}
.section-title{display:flex;flex-wrap:wrap;gap:12px;align-items:center;justify-content:space-between}
.section-title h2,.section-title form{margin:0}
.rule-detail td{padding-top:4px;font-size:.9rem}
tr:has(+.rule-detail)>*{border-bottom:0}
@media(max-width:600px){main{padding:32px 12px 56px}section,article{padding:14px}th,td{padding:8px 6px}}
"""



class Server(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address, ssl_context, app):
        super().__init__(address, Handler)
        self.ssl_context = ssl_context
        self.app = app
        self.audit_lock = Lock()
        self.slots = BoundedSemaphore(12)

    def process_request(self, request, client_address):
        if not self.slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self.slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            request.settimeout(8)
            with self.ssl_context.wrap_socket(request, server_side=True) as secure:
                super().process_request_thread(secure, client_address)
        except OSError:
            self.shutdown_request(request)
        finally:
            self.slots.release()


class Handler(BaseHTTPRequestHandler):
    server_version = "FirewallAuditor"
    sys_version = ""

    def log_message(self, format, *args):
        # Keep request URLs and client credentials out of the audit trail.
        pass

    def authorized(self):
        auth = self.headers.get("Authorization", "").encode()
        self.actor = next((name for name, expected in self.server.app["authorization"].items()
                           if compare_digest(auth, expected)), None)
        return self.actor is not None

    def token(self):
        return digest(self.server.app["token"].encode(), self.actor.encode(), "sha256").hex()

    def helper(self, action, **kwargs):
        return call_helper(self.server.app["helper"], action, self.actor, **kwargs)

    def batch_form(self, action, label, content=""):
        return (f'<form action="/{action}" method="post">'
                f'<input type="hidden" name="token" value="{self.token()}">'
                f'{content}<button type="submit">{label}</button></form>')

    def available_changes(self, data):
        if not data["options"]:
            return "<h3>Enrolled changes</h3><p>No enrolled changes are available for approval.</p>"
        fields = "".join(
            f'<p><label><input type="checkbox" name="port" value="{esc(item["port"])}"> '
            f'TCP {esc(item["port"])} · {esc(item["before"])} → {esc(item["after"])}</label></p>'
            for item in data["options"]
        )
        if data["trial"]:
            fields += "<p>The original rules will be restored at the end of the shared review.</p>"
        elif data["requires_persistence"]:
            fields += ('<p>UFW saves these changes for reboot.</p>'
                       '<input type="hidden" name="persist" value="yes">')
        else:
            fields += '<p><label><input type="checkbox" name="persist" value="yes"> Save after verification</label></p>'
        return "<h3>Enrolled changes</h3>" + self.batch_form("review", "Review selected changes", fields)

    def show_batch(self, batch):
        items = "".join(f'<li>TCP {esc(item["port"])} · {esc(item["before"])} → {esc(item["after"])}'
                        + (f' · {esc(item["reference"])}' if item.get("reference") else "") + "</li>"
                        for item in batch["items"])
        status = {"trial_verified": "Shared review verified", "trial_reset": "Original rules restored"}.get(
            batch["status"], batch["status"].replace("_", " ").title())
        body = f'<article><h3>{esc(status)}</h3><ol>{items}</ol>'
        body += '<p>Separate baseline and after-change checks run from the enrolled clients.</p>'
        body += '<p>Save across reboot: ' + ("Yes" if batch["persist"] else "No") + "</p>"
        if batch["events"]:
            evidence = []
            for event in batch["events"]:
                checks = event.get("baseline") or event.get("verification")
                if checks:
                    label = "Baseline" if "baseline" in event else "After the change"
                    required = {True: "connected", False: "timed out"}.get(checks["required"], "inconclusive")
                    comparison = {True: "connected", False: "timed out"}.get(checks["trial"], "inconclusive")
                    text = f"TCP {event['port']} · {label} · Required client {required} · Comparison client {comparison}"
                else:
                    text = event.get("failure") or event.get("recovery") or ""
                evidence.append(f"<li>{esc(text)}</li>")
            body += "<h4>Verification and change log</h4><ul>" + "".join(evidence) + "</ul>"
        hidden = f'<input type="hidden" name="id" value="{esc(batch["id"])}">'
        if batch["status"] == "review":
            body += self.batch_form("apply", "Approve and apply", hidden)
        elif batch["status"] == "trial_verified":
            body += self.batch_form("end", "Restore original rules", hidden)
        return body + "</article>"

    def send_page(self, status, body, authenticate=False):
        data = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Security-Policy",
                         "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; "
                         "frame-ancestors 'none'; base-uri 'none'")
        if authenticate:
            self.send_header("WWW-Authenticate", 'Basic realm="Firewall Auditor", charset="UTF-8"')
        self.end_headers()
        self.wfile.write(data)

    def render(self, status=200, content="", error=""):
        app = self.server.app
        error_html = f'<p role="alert" class="error">{esc(error)}</p>' if error else ""
        self.send_page(status, f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Firewall Auditor</title><style>{STYLE}</style></head><body><main>
<span class="pill">{esc(app["label"])}</span>
<h1>Firewall Auditor</h1><p class="muted">{esc(app["target"])} · Linux</p>
{error_html}{content}</main></body></html>""")

    def do_GET(self):
        if not self.authorized():
            self.send_page(401, "Sign in to view the firewall audit.", authenticate=True)
            return
        if self.path != "/":
            self.send_page(404, "Not found.")
            return
        try:
            snapshot = self.server.app["snapshot"]()
            chains, rules, gaps = normalize(snapshot["ruleset"])
            if self.server.app["helper"]:
                try:
                    rules.extend(ufw_evidence(self.helper("options")["ufw_rules"]))
                    batches = self.helper("history")
                except (OSError, ValueError):
                    batches = []
                    gaps.append("The change helper is unavailable.")
            else:
                batches = []
            body = configuration(chains, rules, gaps, captured_at(snapshot),
                                 self.batch_form("audit", "Run firewall audit"))
            if batches:
                body += "<section><h2>Your change history</h2>" + "".join(
                    self.show_batch(batch) for batch in batches
                ) + "</section>"
            self.render(content=body)
        except (OSError, ValueError, KeyError, TypeError, AttributeError):
            self.render(503, error="Firewall snapshot unavailable, invalid, or stale. Check the collector.")

    def do_POST(self):
        if not self.authorized():
            self.send_page(401, "Sign in to run an audit.", authenticate=True)
            return
        if (self.path != "/audit" and
                (not self.server.app["helper"] or self.path not in {"/review", "/apply", "/end"})):
            self.send_page(404, "Not found.")
            return
        app = self.server.app
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            length = 0
        if (not 1 <= length <= 2048 or self.headers.get("Transfer-Encoding")
                or self.headers.get_content_type() != "application/x-www-form-urlencoded"):
            self.render(403, error="Audit request rejected. Reload the page and try again.")
            return
        try:
            form = parse_qs(self.rfile.read(length).decode("ascii"), max_num_fields=12)
            token, = form.pop("token")
            if not compare_digest(token.encode(), self.token().encode()):
                raise ValueError("Invalid token.")
        except (KeyError, ValueError, UnicodeError):
            self.render(403, error="Audit request rejected. Reload the page and try again.")
            return
        if self.path != "/audit":
            try:
                if self.path == "/review" and set(form) <= {"port", "persist"}:
                    ports = [int(port) for port in form.get("port", [])]
                    batch = self.helper("prepare", ports=ports, persist=form.get("persist") == ["yes"])
                elif self.path in {"/apply", "/end"} and set(form) == {"id"}:
                    batch_id, = form["id"]
                    batch = self.helper(self.path[1:], id=batch_id)
                else:
                    raise ValueError("Invalid change request.")
                self.render(content=self.show_batch(batch) + '<p><a href="/">Return to dashboard</a></p>')
            except (ValueError, OSError) as error:
                self.render(409, error=str(error) if isinstance(error, ValueError) else "Change helper unavailable.")
            return
        if form:
            self.render(403, error="Unexpected audit request fields.")
            return
        if not self.server.audit_lock.acquire(blocking=False):
            self.render(429, error="An audit is already running. Try again shortly.")
            return
        try:
            changes = ""
            options = {}
            if app["helper"]:
                try:
                    options = self.helper("options")
                    changes = self.available_changes(options)
                except (OSError, ValueError):
                    changes = "<p>Enrolled changes are unavailable. The audit is still available.</p>"
            result = audit(app["snapshot"](), app["policy"], app["model"], app["log_path"],
                           app["target"], options.get("ufw_rules"))
            self.render(content=report_html(result, changes, self.batch_form("audit", "Run audit again"),
                                            refresh_on_request=app.get("refresh_on_request", False)))
        except (OSError, ValueError, KeyError, TypeError, AttributeError):
            self.render(503, error="Audit could not be completed. Check the snapshot and audit log path.")
        finally:
            self.server.audit_lock.release()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--demo", action="store_true")
    mode.add_argument("--config")
    parser.add_argument("--model-url")
    parser.add_argument("--model")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", default=8443, type=int)
    parser.add_argument("--cert", required=True)
    parser.add_argument("--key", required=True)
    parser.add_argument("--log", default="audit.jsonl")
    parser.add_argument("--helper-socket")
    parser.add_argument("--accounts", help="Private JSON file of additional named class accounts")
    args = parser.parse_args()

    user = os.environ.get("FIREWALL_AUDIT_USER", "auditor")
    password = os.environ.get("FIREWALL_AUDIT_PASSWORD", "")
    if not user or ":" in user or len(password) < 16:
        parser.error("Set FIREWALL_AUDIT_PASSWORD to a strong password of at least 16 characters.")
    if args.config and args.model_url is None and args.model is None:
        args.model_url, args.model = os.environ.get("MODEL_URL"), os.environ.get("MODEL_NAME")
    if bool(args.model_url) != bool(args.model):
        parser.error("Set both the model URL and model name, or leave both unset.")
    try:
        model = (Ollama(args.model_url, args.model, os.environ.get("FIREWALL_MODEL_TOKEN"))
                 if args.model else None)
        config = read_json(args.config, 65536) if args.config else {
            "target": "Sample Ubuntu host", "policy": REVIEW_POLICY,
        }
        if not isinstance(config["target"], str) or (args.config and not os.path.isabs(config["snapshot"])):
            raise ValueError("Use a target name and an absolute snapshot path.")
        accounts_path = args.accounts or config.get("accounts")
        accounts = read_json(accounts_path, 65536) if accounts_path else {}
        accounts[user] = password
        if any(not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", name)
               or not isinstance(secret, str) or len(secret) < 16 for name, secret in accounts.items()):
            raise ValueError("Invalid named account configuration.")
        app = {
            "authorization": {name: b"Basic " + base64.b64encode(f"{name}:{secret}".encode())
                              for name, secret in accounts.items()},
            "helper": args.helper_socket or config.get("helper_socket"),
            "token": token_urlsafe(32), "policy": load_policy(config["policy"]),
            "label": "Live snapshot" if args.config else "Demo · sample rules",
            "target": config["target"][:100],
            "snapshot": partial(load_snapshot, config["snapshot"], 180) if args.config else review_snapshot,
            "model": model, "log_path": args.log,
        }
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(args.cert, args.key)
        with Server((args.host, args.port), context, app) as server:
            print(f"Firewall Auditor serving HTTPS on {args.host}:{server.server_port}", flush=True)
            server.serve_forever()
    except KeyboardInterrupt:
        pass
    except (OSError, ValueError, KeyError, TypeError) as error:
        parser.exit(1, f"Startup error: {error}\n")


if __name__ == "__main__":
    main()
