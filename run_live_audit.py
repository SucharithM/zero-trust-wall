"""Run a one-command, read-only HTTPS audit of this Linux machine."""
import argparse
import base64
from http.client import HTTPSConnection
import os
from pathlib import Path
import re
from secrets import token_urlsafe
import shutil
import socket
import ssl
import subprocess
import sys
from tempfile import TemporaryDirectory
from threading import Thread
from urllib.parse import urlencode

from deploy.collect import NFT_LIST_ARGS, capture
from firewall_auditor.__main__ import Server
from firewall_auditor.agent import Ollama
from firewall_auditor.core import load_policy, read_json


HOST = "127.0.0.1"
SUDO = "/usr/bin/sudo"
NFT = "/usr/sbin/nft"


def live_snapshot():
    try:
        return capture((SUDO, "-n", NFT))
    except (OSError, subprocess.SubprocessError) as error:
        print("Could not read nftables. If sudo access expired, restart the launcher.", file=sys.stderr)
        raise OSError("Live firewall capture failed.") from error


def certificate(directory):
    cert, key = directory / "cert.pem", directory / "key.pem"
    subprocess.run([
        "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
        "-subj", "/CN=localhost", "-addext", f"subjectAltName=IP:{HOST}",
        "-keyout", str(key), "-out", str(cert),
    ], check=True, capture_output=True, timeout=20)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(cert, key)
    return context, cert


def verify_audit(port, cert, authorization):
    client = HTTPSConnection(HOST, port, context=ssl.create_default_context(cafile=str(cert)), timeout=90)
    try:
        headers = {"Authorization": authorization.decode("ascii")}
        client.request("GET", "/", headers=headers)
        response = client.getresponse()
        dashboard = response.read().decode()
        token = re.search(r'name="token" value="([0-9a-f]+)"', dashboard)
        if response.status != 200 or not token:
            raise ValueError("Could not open the live dashboard. Check the capture message above.")
        headers["Content-Type"] = "application/x-www-form-urlencoded"
        client.request("POST", "/audit", urlencode({"token": token[1]}), headers)
        response = client.getresponse()
        report = response.read().decode()
        count = re.search(r'>(\d+ findings?) · Audit ', report)
        if response.status != 200 or not count:
            raise ValueError("The HTTPS firewall audit did not complete.")
        return count[1]
    finally:
        client.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--policy", type=Path, help="A configuration JSON file containing the service policy")
    parser.add_argument("--model", help="An installed model from the local Ollama server")
    parser.add_argument("--check", action="store_true", help="Run the live audit and exit")
    args = parser.parse_args()
    if sys.platform != "linux" or sys.version_info < (3, 11):
        parser.error("Run this in your Linux VM with Python 3.11 or newer.")
    if os.geteuid() == 0:
        parser.error("Run the launcher as your regular user. It requests sudo for nftables only.")
    if any(not os.access(path, os.X_OK) for path in (SUDO, NFT, "/usr/bin/ss")) or not shutil.which("openssl"):
        parser.error("Install sudo, nftables, iproute2, and OpenSSL first.")

    try:
        policy = load_policy(read_json(args.policy, 65536)["policy"]) if args.policy else {}
        print("Approve sudo access to read the active nftables rules.", flush=True)
        subprocess.run([SUDO, NFT, *NFT_LIST_ARGS], stdout=subprocess.DEVNULL, check=True)
        password = token_urlsafe(24)
        authorization = b"Basic " + base64.b64encode(f"auditor:{password}".encode())
        with TemporaryDirectory(prefix="firewall-audit-") as directory:
            work = Path(directory)
            context, cert = certificate(work)
            app = {
                "authorization": {"auditor": authorization},
                "token": token_urlsafe(32),
                "helper": None,
                "policy": policy,
                "label": "Live snapshot",
                "target": socket.gethostname(),
                "snapshot": live_snapshot,
                "model": Ollama("http://127.0.0.1:11434", args.model) if args.model else None,
                "log_path": work / "audit.jsonl",
                "refresh_on_request": True,
            }
            with Server((HOST, 0), context, app) as server:
                worker = Thread(target=server.serve_forever, daemon=True)
                worker.start()
                try:
                    count = verify_audit(server.server_port, cert, authorization)
                    print(f"Live HTTPS audit passed · {count}", flush=True)
                    if not args.check:
                        print(f"Dashboard https://{HOST}:{server.server_port}/")
                        print(f"Sign in as auditor with password {password}")
                        print(f"Certificate for browser trust {cert}")
                        print("Run audit again reads your active firewall. Press Ctrl+C to stop.", flush=True)
                        worker.join()
                finally:
                    server.shutdown()
                    worker.join()
    except KeyboardInterrupt:
        pass
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        parser.exit(1, f"Live audit failed. {error}\n")


if __name__ == "__main__":
    main()
