"""Local firewall helper. Only the authorized web Unix account can reach its socket."""
import argparse
import ipaddress
import json
import os
from pathlib import Path
import re
import socket
from socketserver import StreamRequestHandler, UnixStreamServer
import sys
import time

from .backends import Nftables, Ufw, command
from .core import read_json
from .remediation import Coordinator


LIMIT = 65536


def call_helper(path, action, actor, **args):
    payload = json.dumps({"action": action, "actor": actor, **args}).encode() + b"\n"
    with socket.socket(socket.AF_UNIX) as client:
        client.settimeout(240)
        client.connect(path)
        client.sendall(payload)
        with client.makefile("rb") as reply:
            answer = json.loads(reply.readline(LIMIT + 1))
    if "error" in answer:
        raise ValueError(answer["error"])
    return answer["result"]


class RequestHandler(StreamRequestHandler):
    def handle(self):
        self.request.settimeout(3)
        actor = None
        action = None
        try:
            body = self.rfile.readline(LIMIT + 1)
            if not body or len(body) > LIMIT:
                raise ValueError("Invalid helper request.")
            item = json.loads(body)
            actor = item["actor"]
            if not isinstance(actor, str) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", actor):
                raise ValueError("Invalid operator identity.")
            app = self.server.coordinator
            def options():
                return {"trial": app.trial, "options": app.options(),
                        "ufw_rules": app.backend.read() if isinstance(app.backend, Ufw) else {},
                        "requires_persistence": getattr(app.backend, "requires_persistence", False)}

            actions = {
                "options": options,
                "history": lambda: app.history(actor)[:5],
                "prepare": lambda: app.prepare(actor, item["ports"], item["persist"]),
                "apply": lambda: app.apply(actor, item["id"]),
                "end": lambda: app.end(actor, item["id"]),
            }
            action = item["action"]
            response = {"result": actions[action]()}
        except ValueError as error:
            response = {"error": str(error)}
        except (KeyError, OSError, TypeError, AttributeError):
            response = {"error": "The helper could not complete this request."}
        try:
            if "error" in response and action in {"prepare", "apply", "end"}:
                with (self.server.coordinator.directory / "rejected.jsonl").open("a") as log:
                    log.write(json.dumps({"timestamp": time.time(), "actor": actor,
                                          "operation": action, "reason": response["error"]}) + "\n")
            payload = json.dumps(response).encode() + b"\n"
            if len(payload) > LIMIT:
                payload = b'{"error":"Helper response exceeded the size limit."}\n'
            self.wfile.write(payload)
        except OSError:
            pass


def verifier(config):
    targets = config["witnesses"]
    comparison = "comparison" if "comparison" in targets else "trial"
    if set(targets) != {"required", comparison}:
        raise ValueError("Configure required and comparison witness clients.")
    hosts = {role: ipaddress.IPv4Address(targets[key])
             for role, key in (("required", "required"), ("trial", comparison))}
    if len(set(hosts.values())) != 2 or any(
        not address.is_private or address.is_loopback or address.is_unspecified for address in hosts.values()
    ):
        raise ValueError("Witnesses must be two distinct private hosts.")
    key, host_keys = config["ssh_key"], config["known_hosts"]
    if not all(os.path.isabs(file) for file in (key, host_keys)):
        raise ValueError("Witness key paths must be absolute.")

    def check(port, restricted):
        result = {}
        for role, host in hosts.items():
            value = command(
                "/usr/bin/ssh", "-F", "/dev/null", "-i", key, "-o", "IdentitiesOnly=yes",
                "-o", "PasswordAuthentication=no", "-o", "BatchMode=yes",
                "-o", "StrictHostKeyChecking=yes", "-o", f"UserKnownHostsFile={host_keys}",
                "-o", "GlobalKnownHostsFile=/dev/null",
                "-o", "ConnectTimeout=3", "-T", f"firewall-witness@{host}", str(port),
            ).strip()
            result[role] = {"connected": True, "timed_out": False}.get(value)
        return result
    return check


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True)
    parser.add_argument("--socket", default="/run/firewall-auditor-helper/control.sock")
    parser.add_argument("--state", default="/var/lib/firewall-auditor-helper")
    parser.add_argument("--provision-nft", action="store_true")
    args = parser.parse_args()
    config = read_json(args.config, LIMIT)
    desired = {int(port): str(ipaddress.IPv4Network(source["approved"]))
               for port, source in config["rules"].items()}
    protected = {22, 3389, 8443, *config.get("protected_ports", [])}
    if not desired or len(desired) > 8 or any(port in protected or not 1024 <= port <= 65535
                                             for port in desired):
        parser.error("Enroll one to eight non-management test ports.")
    backend_name = config["backend"]
    trial = config["mode"] in {"shared", "trial"}
    if not trial and config["mode"] != "personal":
        parser.error("Choose shared or personal mode.")
    if backend_name == "nftables":
        backend = Nftables(desired, Path(args.state) / "managed.nft")
    elif backend_name == "ufw" and not trial:
        backend = Ufw(desired)
    else:
        parser.error("Choose nftables, or UFW in personal mode.")

    if args.provision_nft:
        if backend_name != "nftables":
            parser.error("UFW rules must be enrolled through the firewall manager.")
        initial = {int(port): str(ipaddress.IPv4Network(source["initial"]))
                   for port, source in config["rules"].items()}
        if any(not ipaddress.IPv4Network(desired[port]).subnet_of(ipaddress.IPv4Network(network))
               or desired[port] == network for port, network in initial.items()):
            parser.error("Each approved range must be narrower than the initial range.")
        backend.provision(initial)
        return

    coordinator = Coordinator(backend, desired, verifier(config), args.state, trial=trial)
    Path(args.socket).unlink(missing_ok=True)
    with UnixStreamServer(args.socket, RequestHandler) as server:
        os.chmod(args.socket, 0o660)
        server.coordinator = coordinator
        server.timeout = 2
        while True:
            coordinator.recover()
            server.handle_request()


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, KeyError, TypeError) as error:
        sys.exit(f"Firewall helper startup failed: {error}")
