"""SSH forced command that checks only the pre-enrolled service and ports."""
import ipaddress
import os
from pathlib import Path
import socket
import sys

from .core import read_json


def main():
    config = read_json(Path("/etc/firewall-auditor/witness.json"), 4096)
    target = ipaddress.IPv4Address(config["target"])
    port = int(os.environ.get("SSH_ORIGINAL_COMMAND", ""))
    source = ipaddress.IPv4Address(os.environ["SSH_CONNECTION"].split()[2])
    if (not target.is_private or target.is_loopback or port not in config["ports"]
            or str(source) not in config["sources"]):
        sys.exit("Target not enrolled.")
    try:
        with socket.create_connection((str(target), port), timeout=2, source_address=(str(source), 0)):
            print("connected")
    except TimeoutError:
        print("timed_out")
    except OSError:
        print("inconclusive")


if __name__ == "__main__":
    main()
