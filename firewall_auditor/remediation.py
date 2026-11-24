"""Durable, single-use approvals for source-narrowing batches."""
import ipaddress
import json
import os
from pathlib import Path
import re
import tempfile
import time
from uuid import uuid4


def atomic_write(path, text):
    with tempfile.NamedTemporaryFile(mode="w", dir=path.parent, delete=False) as file:
        temporary = Path(file.name)
        try:
            file.write(text)
            file.flush()
            os.fsync(file.fileno())
            os.replace(temporary, path)
            directory = os.open(path.parent, os.O_RDONLY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        finally:
            temporary.unlink(missing_ok=True)


class Coordinator:
    def __init__(self, backend, desired, verify, directory, *, trial=False, now=time.time):
        self.backend = backend
        self.desired = desired
        self.verify = verify
        self.directory = Path(directory)
        self.trial = trial
        self.now = now

    def _path(self, batch_id):
        if not re.fullmatch("[a-f0-9]{32}", batch_id):
            raise ValueError("Unknown batch.")
        return self.directory / (batch_id + ".json")

    def _save(self, batch):
        atomic_write(self._path(batch["id"]), json.dumps(batch))

    def _load(self, path):
        batch = json.loads(path.read_text())
        for key in ("before", "saved_before", "goal"):
            batch[key] = {int(port): source for port, source in batch[key].items()}
        return batch

    def history(self, actor=None):
        batches = [self._load(path) for path in self.directory.glob("*.json")]
        return sorted((b for b in batches if actor is None or b["actor"] == actor),
                      key=lambda batch: batch["created"], reverse=True)

    def options(self):
        current = self.backend.read()
        result = []
        for port, source in sorted(self.desired.items()):
            before = ipaddress.IPv4Network(current[port])
            after = ipaddress.IPv4Network(source)
            if before != after and after.subnet_of(before):
                result.append({"port": port, "before": str(before), "after": str(after)})
        return result

    def prepare(self, actor, ports, persist):
        if (not isinstance(ports, list) or not 1 <= len(ports) <= 8
                or any(type(port) is not int for port in ports) or len(set(ports)) != len(ports)
                or type(persist) is not bool or (self.trial and persist)):
            raise ValueError("Select a valid batch and save option.")
        if getattr(self.backend, "requires_persistence", False) and not persist:
            raise ValueError("Approve saving these UFW changes as part of the batch.")
        if self.trial and any(item["status"] in {"applying", "trial_verified", "recovery_needed"}
                              or (item["status"] == "review" and item["actor"] != actor
                                  and self.now() < item["deadline"])
                              for item in self.history()):
            raise ValueError("The shared review is already reserved.")
        before = self.backend.read()
        options = {item["port"]: item for item in self.options()}
        references = self.backend.references() if hasattr(self.backend, "references") else {}
        if before != self.backend.read() or any(port not in options for port in ports):
            raise ValueError("Only current, enrolled restrictions can be approved.")
        goal = {**before, **{port: options[port]["after"] for port in ports}}
        batch = {
            "id": uuid4().hex, "actor": actor, "created": self.now(), "deadline": self.now() + 300,
            "status": "review", "before": before, "goal": goal,
            "saved_before": self.backend.read_saved(), "persist": persist,
            "items": [{**options[port], "reference": references.get(port)} for port in ports],
            "attempted": [], "events": [],
        }
        self._save(batch)
        return batch

    def apply(self, actor, batch_id):
        try:
            batch = self._load(self._path(batch_id))
        except FileNotFoundError as error:
            raise ValueError("Unknown batch.") from error
        if batch["actor"] != actor or batch["status"] != "review" or self.now() >= batch["deadline"]:
            raise ValueError("Approval does not match an active proposal.")
        if any(item["status"] in {"applying", "trial_verified", "recovery_needed"}
               for item in self.history()):
            raise ValueError("A change is already active or needs recovery.")
        before = batch["before"]
        references = self.backend.references() if hasattr(self.backend, "references") else {}
        if (self.backend.read() != before or self.backend.read_saved() != batch["saved_before"]
                or any(item.get("reference") and references.get(item["port"]) != item["reference"]
                       for item in batch["items"])):
            batch["status"] = "stale"
            self._save(batch)
            raise ValueError("Firewall changed after review. Run a new audit.")
        batch["status"] = "applying"
        batch["deadline"] = self.now() + 300
        self._save(batch)
        expected = before.copy()
        try:
            for item in batch["items"]:
                port = item["port"]
                baseline = self.verify(port, False)
                batch["events"].append({"port": port, "baseline": baseline})
                if baseline != {"required": True, "trial": True}:
                    raise ValueError("Baseline checks did not both connect.")
                if self.backend.read() != expected or self.now() >= batch["deadline"]:
                    raise ValueError("Configuration drift or approval deadline reached.")
                batch["attempted"].append(port)
                self._save(batch)
                self.backend.replace(port, item["before"], item["after"])
                expected[port] = item["after"]
                if self.backend.read() != expected:
                    raise ValueError("Readback did not match the approved rule.")
                outcome = self.verify(port, True)
                batch["events"].append({"port": port, "readback": "matched", "verification": outcome})
                if outcome != {"required": True, "trial": False}:
                    raise ValueError("Client checks did not confirm the approved restriction.")
                self._save(batch)
            if batch["persist"]:
                self.backend.save(expected, batch["saved_before"])
                if self.backend.read_saved() != expected:
                    raise ValueError("Saved configuration did not match the approved rules.")
            batch["status"] = "trial_verified" if self.trial else ("saved" if batch["persist"] else "verified")
            self._save(batch)
        except (ValueError, OSError, KeyError, TypeError) as error:
            batch["events"].append({"failure": str(error)})
            self._rollback(batch, "rolled_back")
        return batch

    def _rollback(self, batch, status):
        try:
            for port in reversed(batch["attempted"]):
                if hasattr(self.backend, "restore_transient"):
                    self.backend.restore_transient(port, batch["before"][port], batch["goal"][port])
                source = self.backend.read()[port]
                if source != batch["before"][port]:
                    if source != batch["goal"][port]:
                        raise ValueError("Independent firewall edit detected.")
                    self.backend.replace(port, source, batch["before"][port])
                if self.backend.read()[port] != batch["before"][port]:
                    raise ValueError("Rollback readback failed.")
            saved = self.backend.read_saved()
            if saved != batch["saved_before"]:
                if saved != batch["goal"]:
                    raise ValueError("Independent saved configuration edit detected.")
                self.backend.save(batch["saved_before"], saved)
            if self.backend.read_saved() != batch["saved_before"]:
                raise ValueError("Saved rollback readback failed.")
            batch["status"] = status
        except (ValueError, OSError, KeyError) as error:
            batch["events"].append({"recovery": str(error)})
            batch["status"] = "recovery_needed"
        self._save(batch)

    def recover(self):
        for batch in self.history():
            if batch["status"] == "applying":
                self._rollback(batch, "rolled_back")
            elif batch["status"] == "trial_verified" and self.now() >= batch["deadline"]:
                self._rollback(batch, "trial_reset")
            elif batch["status"] == "review" and self.now() >= batch["deadline"]:
                self._path(batch["id"]).unlink()

    def end(self, actor, batch_id):
        for batch in self.history(actor):
            if batch["id"] == batch_id and batch["status"] == "trial_verified":
                self._rollback(batch, "trial_reset")
                return batch
        raise ValueError("No active shared review to restore.")
