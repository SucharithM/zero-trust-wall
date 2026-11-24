"""Exercise the actual HTTPS entry point with optional real Ollama inference."""
import argparse
import base64
import http.client
import os
from pathlib import Path
import re
from secrets import token_urlsafe
import socket
import ssl
import subprocess
import sys
from tempfile import TemporaryDirectory
from socketserver import UnixStreamServer
from threading import Thread
from urllib.parse import urlencode


def check(model, remediation=False, model_unavailable=False):
    with TemporaryDirectory() as directory, socket.socket() as unavailable:
        work = Path(directory)
        cert, key = work / "cert.pem", work / "key.pem"
        subprocess.run([
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
            "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1",
            "-keyout", str(key), "-out", str(cert),
        ], check=True, capture_output=True)
        password = token_urlsafe(24)
        args = [
            sys.executable, "-m", "firewall_auditor", "--demo", "--port", "0",
            "--cert", str(cert), "--key", str(key), "--log", str(work / "audit.jsonl"),
        ]
        helper = None
        if remediation:
            from firewall_auditor.helper import RequestHandler
            from firewall_auditor.remediation import Coordinator
            from tests.test_remediation import Firewall

            journal = work / "journal"
            journal.mkdir()
            # Keep the Unix socket path short enough for macOS.
            socket_path = f"/tmp/fwa-{token_urlsafe(8)}.sock"
            helper = UnixStreamServer(socket_path, RequestHandler)
            backend = Firewall()
            helper.coordinator = Coordinator(
                backend, {8081: "192.0.2.8/32", 8082: "192.0.2.8/32"},
                lambda port, restricted: {"required": True, "trial": not restricted},
                journal, trial=True,
            )
            Thread(target=helper.serve_forever, daemon=True).start()
            args += ["--helper-socket", socket_path]
        if model_unavailable:
            unavailable.bind(("127.0.0.1", 0))
            unused_port = unavailable.getsockname()[1]
            args += ["--model-url", f"http://127.0.0.1:{unused_port}", "--model", "unavailable"]
        elif model:
            args += ["--model-url", "http://127.0.0.1:11434", "--model", model]
        env = {**os.environ, "FIREWALL_AUDIT_USER": "auditor",
               "FIREWALL_AUDIT_PASSWORD": password}
        with subprocess.Popen(args, env=env, stdout=subprocess.PIPE, text=True) as process:
            try:
                line = process.stdout.readline()
                if not line:
                    raise RuntimeError("The HTTPS service did not start.")
                port = int(line.rsplit(":", 1)[-1])
                auth = "Basic " + base64.b64encode(f"auditor:{password}".encode()).decode()
                trusted = ssl.create_default_context(cafile=str(cert))

                def request(method, path, headers=None, body=None, context=trusted):
                    conn = http.client.HTTPSConnection("127.0.0.1", port, context=context, timeout=90)
                    try:
                        conn.request(method, path, body=body, headers=headers or {})
                        response = conn.getresponse()
                        return response.status, response.read().decode()
                    finally:
                        conn.close()

                try:
                    request("GET", "/", context=ssl.create_default_context())
                except ssl.SSLCertVerificationError:
                    print("Unknown certificate rejected; explicit certificate trust works.")
                else:
                    raise AssertionError("Unexpected certificate trust")
                assert request("GET", "/")[0] == 401
                headers = {"Authorization": auth}
                code, page = request("GET", "/", headers)
                assert code == 200 and "Current firewall configuration" in page and "<time " in page
                assert "Demo · sample rules" in page
                headers["Content-Type"] = "application/x-www-form-urlencoded"
                assert request("POST", "/audit", headers, urlencode({"token": "bad"}))[0] == 403
                token = re.search('name="token" value="([^"]+)"', page).group(1)
                code, page = request("POST", "/audit", headers, urlencode({"token": token}))
                assert code == 200 and "5 findings" in page
                headings = ["Current firewall configuration", "Rules to review", "What Ollama did", "What to change"]
                assert [page.index(item) for item in headings] == sorted(page.index(item) for item in headings)
                for label in ("Captured rule", "Expected access", "Review suggested change",
                              "Manual change and verification steps", "Run audit again"):
                    assert label in page
                assert 'href="#rule-R1"' in page and 'id="rule-R1"' in page
                assert "ip saddr 198.51.100.7/32 tcp dport 9443 accept" in page and "@team_clients" in page
                assert "End-to-end reachability is unverified." in page
                audit_log = (work / "audit.jsonl").read_text()
                assert "accept_rules" not in audit_log
                if model_unavailable:
                    assert "Model unavailable" in page and "No validated response" in page
                else:
                    assert "Completed" in audit_log, audit_log
                if model:
                    assert model in page and "Audit data sent" in page and "Validated response" in page
                    assert "Ollama suggests reviewing" in page
                elif not model_unavailable:
                    assert "Ollama was disabled" in page
                print("HTTPS authentication, report order, five findings and model status verified.")
                if remediation:
                    def post(path, fields):
                        return request("POST", path, headers, urlencode({"token": token, **fields}, doseq=True))

                    assert "Review selected changes" in page
                    code, review = post("/review", {"port": [8081, 8082]})
                    assert code == 200 and "Approve and apply" in review and not backend.writes
                    batch_id = re.search('name="id" value="([^"]+)"', review).group(1)
                    code, applied = post("/apply", {"id": batch_id})
                    assert code == 200 and "Shared review verified" in applied and "Restore original rules" in applied
                    assert [port for port, _ in backend.writes] == [8081, 8082]
                    assert post("/apply", {"id": batch_id})[0] == 409
                    code, reset = post("/end", {"id": batch_id})
                    assert code == 200 and "Original rules restored" in reset
                    assert backend.read() == backend.saved
                    print("HTTPS review, ordered approval, replay rejection and restoration passed with a test backend.")
            finally:
                process.terminate()
                if helper:
                    helper.shutdown()
                    helper.server_close()
                    Path(socket_path).unlink(missing_ok=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    model_mode = parser.add_mutually_exclusive_group()
    model_mode.add_argument("--model")
    model_mode.add_argument("--model-unavailable", action="store_true")
    parser.add_argument("--remediation-fixture", action="store_true")
    args = parser.parse_args()
    check(args.model, args.remediation_fixture, args.model_unavailable)
