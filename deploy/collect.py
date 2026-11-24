"""Collect local firewall and TCP listener evidence without changing network state."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time


DESTINATION = Path("/var/lib/firewall-auditor/snapshot.json")
NFT_LIST_ARGS = ("-j", "-n", "-a", "list", "ruleset")


def read_command(*args):
    with tempfile.TemporaryFile() as output:
        subprocess.run(args, stdout=output, check=True, timeout=8)
        output.seek(0)
        data = output.read(2 * 1024 * 1024 + 1)
    if len(data) > 2 * 1024 * 1024:
        raise ValueError("Firewall evidence exceeds the collector size limit.")
    return data


def capture(nft_command=("/usr/sbin/nft",)):
    ruleset = json.loads(read_command(*nft_command, *NFT_LIST_ARGS))
    listeners = None
    try:
        lines = read_command("/usr/bin/ss", "-H", "-ltn").decode().splitlines()
        listeners = sorted({int(line.split()[3].rsplit(":", 1)[-1]) for line in lines})
    except (subprocess.SubprocessError, OSError, ValueError, IndexError):
        print("TCP listening socket evidence is unavailable.", flush=True)
    return {"captured_at": time.time(), "ruleset": ruleset, "listeners": listeners}


def main():
    snapshot = capture()
    fd, name = tempfile.mkstemp(prefix=".snapshot-", dir=DESTINATION.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as output:
            json.dump(snapshot, output, separators=(",", ":"))
            output.flush()
            os.fchmod(output.fileno(), 0o640)
        os.replace(name, DESTINATION)
    finally:
        Path(name).unlink(missing_ok=True)


if __name__ == "__main__":
    main()
