# Firewall Auditor

For a shared deployment, follow the [Ubuntu installation instructions](#install-on-an-ubuntu-pc-or-vm).

From the project folder on your Linux PC or VM, run `python3 run_live_audit.py`
for a one-command read-only audit of the active firewall.

A Python firewall auditor for a Linux PC or VM running nftables. The HTTPS console
shows the current inbound rules, explains how they compare with your access policy,
and suggests changes you can make in your firewall manager.
With the optional local helper enabled, it applies approved batches on nftables
or UFW, verifies access from two enrolled clients, and records the outcome.
Personal installs can save verified changes across reboot. Shared reviews reset
their test rules for the next reviewer.

The audited host exports a local snapshot through a small collector. The web app
runs without firewall privileges. It calls an operator-configured Ollama endpoint,
lets the model choose approved evidence tools and suggest which finding to review
first. The report shows the model inputs and validated decisions. The rule engine
generates findings and changes with or without Ollama.

## Try the HTTPS demo

Requirements are Python 3.11+ and OpenSSL. The demo uses sample rules and labels
them as such. Ollama is optional in both sample and live audits.

```sh
mkdir -p .local
chmod 700 .local
openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
  -subj /CN=localhost -addext 'subjectAltName=DNS:localhost,IP:127.0.0.1' \
  -keyout .local/key.pem -out .local/cert.pem
export FIREWALL_AUDIT_PASSWORD="$(openssl rand -hex 18)"
printf 'Local demo password: %s\n' "$FIREWALL_AUDIT_PASSWORD"
python3 -m firewall_auditor --demo --cert .local/cert.pem --key .local/key.pem
```

Open `https://localhost:8443` after explicitly trusting the local demo
certificate in your test client. Sign in as `auditor` with the generated password.
For a command-line check with certificate verification, run this from the same shell:

```sh
curl --cacert .local/cert.pem --user "auditor:$FIREWALL_AUDIT_PASSWORD" https://localhost:8443/
```

Use a model already installed by Ollama by adding
`--model-url http://127.0.0.1:11434 --model <installed-model>` to the app command.
You can use an endpoint on another machine via trusted HTTPS, or via an
operator-managed SSH tunnel that listens on app-host loopback. Keep the model
endpoint private. If the HTTPS endpoint uses bearer authentication, set
`FIREWALL_MODEL_TOKEN` on the app host. No paid Gemini account is needed. In the
isolated Cyber Range, the model host must be reachable from the Ubuntu VM
without an external route.

## Install on an Ubuntu PC or VM

Use Python 3.11 or newer, nftables, and iproute2 on the Linux machine whose rules
you want to audit. These service instructions use Ubuntu and systemd. Stage the
source and any model before going offline. Use a certificate whose DNS name or
IP matches the dashboard address. Clients must trust its
issuing CA. For a class-managed CA, share only its public trust certificate,
never the service's private key.

1. Install the code and units as an administrator:

   ```sh
   sudo useradd --system --user-group --no-create-home --shell /usr/sbin/nologin firewall-auditor
   sudo install -d -m 0755 /opt/firewall-auditor
   sudo cp -R firewall_auditor deploy /opt/firewall-auditor/
   sudo install -m 0644 deploy/*.service deploy/*.timer /etc/systemd/system/
   sudo install -d -o root -g firewall-auditor -m 0750 /etc/firewall-auditor
   sudo install -o root -g firewall-auditor -m 0640 config/range.example.json /etc/firewall-auditor/range.json
   ```

2. Edit `/etc/firewall-auditor/range.json` with `sudoedit`. Replace the example
   host label and documentation-only CIDRs with the known-good policy for the
   VM. Each TCP service lists the only source networks that should be allowed.
   Omit ports without a known policy. Keep real policy files out of Git.
3. Install the trusted certificate chain and key into `/etc/firewall-auditor/`
   as `cert.pem` and `key.pem`. Set the key's owner and group to
   `root:firewall-auditor` and its mode to `0640`. Create
   `/etc/firewall-auditor/environment` with owner `root:root` and mode `0600`.
   Use a strong password and loopback binding for access from the same machine.
   Use the assigned private address when sharing the console with approved users.
   Add both model settings to enable Ollama. Leave both out for a rule-based audit.

   ```dotenv
   AUDIT_BIND=127.0.0.1
   FIREWALL_AUDIT_USER=auditor
   FIREWALL_AUDIT_PASSWORD=replace-with-a-generated-password
   MODEL_URL=http://127.0.0.1:11434
   MODEL_NAME=replace-with-an-installed-model
   ```

4. Start the collector and enable both services. The collector refreshes evidence
   about every 30 seconds. A snapshot older than three minutes is rejected.

   ```sh
   sudo systemctl daemon-reload
   sudo systemctl start firewall-auditor-collect.service
   sudo systemctl enable --now firewall-auditor-collect.timer firewall-auditor.service
   systemctl status firewall-auditor.service firewall-auditor-collect.timer
   sudo journalctl -u firewall-auditor-collect.service -u firewall-auditor.service -n 30
   ```

5. Open the trusted HTTPS URL at port 8443. Check the capture time, run an audit,
   and follow a finding from the captured rule to its suggested change. After a
   legitimate change, wait for the collector to refresh and rerun the audit.

For the Cyber Range, open the trusted HTTPS URL from a second class machine. Ask
each team to confirm browser access and an audit result. Use a range host and
policy approved for class viewing. Provide the URL and credentials through the
class-approved channel. A long-term shared service should use individual
accounts and a managed HTTPS gateway.

## Test and collect Phase 3 evidence

```sh
python3 -m unittest discover -s tests -v
python3 -m tests.check_https
python3 -m tests.check_https --model-unavailable
python3 -m tests.check_https --model <installed-model>
python3 -m tests.check_https --model <installed-model> --remediation-fixture
```

The tests exercise the firewall checks, model tool boundary, HTML escaping, and
stale snapshot handling. The HTTPS check starts a loopback server and checks
certificate validation, authentication, and request validation, then runs an
end-to-end audit. With `--model`, it uses a real model with sample firewall data.
The live Cyber Range check is separate.

Save Phase 3 evidence in the Git-ignored `.local/` directory. In the private
class submission, record the GitHub URL, tested HTTPS URL, service locations,
contact details, and each team's access check. Include a screenshot of the
HTTPS result from a second class machine. Use demo data for public screenshots.
Keep deployment addresses, hostnames, contact details, passwords, live snapshots,
private keys, and access tokens out of public reports and Git.

## Repository layout

- `firewall_auditor/` serves HTTPS, reads snapshots, and runs the bounded audit.
- `config/` contains the example policy and snapshot path.
- `deploy/` contains the Ubuntu collector and service units.
- `tests/` contains fixtures, unit tests, and the HTTPS smoke test.

The analyzer handles nftables IPv4 and IPv6 inbound rules with a single TCP
destination port, static source sets, one supported jump path, and unrestricted
accepts. It marks other expressions or ambiguous paths for manual review, shows
chain defaults, and reports configured rule scope. Audit history is stored
locally as JSON lines. The log records evidence references and selected tools;
regularly archive it according to your deployment's retention needs.

See the [nftables reference](https://netfilter.org/projects/nftables/manpage.html)
and [Ollama structured output documentation](https://docs.ollama.com/capabilities/structured-outputs)
for the external interfaces used here.

## Enable approved firewall changes

Use the existing Ubuntu installation steps first. Keep the deployment private.
The web service stays unprivileged, and the write helper listens on a protected
Unix socket. Run the initial setup and recovery from the VM console.

1. Provision two distinct verification clients. On each client install the
   Python package directory at `/opt/firewall-auditor/firewall_auditor`; create
   the dedicated `firewall-witness` OpenSSH account and install
   `config/witness.example.json` as `/etc/firewall-auditor/witness.json`. Set
   the target address, the exact two test ports, and the witness client's own
   IPv4 address in `sources`. This file may be readable
   by the dedicated witness account and must be owned by root.
2. Create a dedicated SSH key on the audited VM for verification and restrict the
   witness accounts' authorized key entries to the following forced command.
   Substitute the helper's public key. Verify both witness host keys through
   their consoles and pin them in the helper's `known_hosts` file.

   ```text
   restrict,command="cd /opt/firewall-auditor && /usr/bin/python3 -m firewall_auditor.witness" ssh-ed25519 <helper-public-key>
   ```

3. Copy `config/helper.example.json` to `/etc/firewall-auditor/helper.json`
   as root, mode `0600`. Replace the documentation addresses with the observed
   private addresses. Provide the protected key and known-hosts file. Run two
   disposable TCP listeners on the target, bound to its private IPv4 address.
   Use an empty directory if using Python's HTTP test server. Use the same
   expected sources in `range.json` so the report and helper agree. Verify the
   target sees two different client addresses and both clients can connect
   before applying a change.
4. Select a backend. Use a single manager per test VM.

   - **Native nftables:** Provision the dedicated test table. Load it once after
     checking that the table does not already exist. For reboot persistence,
     include the verified managed file in your administrator-owned
     `/etc/nftables.conf` and enable the distro's nftables service. Preserve
     any existing management rules. The helper edits only the managed test
     rules and never reloads the entire config itself.

     ```sh
     sudo install -d -o root -g firewall-auditor -m 0700 /var/lib/firewall-auditor-helper
     sudo env PYTHONPATH=/opt/firewall-auditor /usr/bin/python3 -m firewall_auditor.helper \
       --config /etc/firewall-auditor/helper.json --provision-nft
     sudo nft -f /var/lib/firewall-auditor-helper/managed.nft
     ```

     Add `include "/var/lib/firewall-auditor-helper/managed.nft"` to the
     existing startup configuration from the VM console. Check it with
     `sudo nft -c -f /etc/nftables.conf` before testing a reboot.
   - **UFW:** Choose `"backend": "ufw", "mode": "personal"`. Use an already
     configured test VM with UFW active. Keep console, SSH and dashboard access
     available. For each eligible TCP port, enroll one simple IPv4 allow rule
     with the UFW comment `firewall-auditor-<port>`. Use a specific IPv4
     source CIDR, and a deny-by-default path for the test service. Rule writes
     use UFW's native saved configuration.
5. Add `"helper_socket": "/run/firewall-auditor-helper/control.sock"` to
   `range.json`. On the shared instance use `"mode": "shared"` in the helper
   config and give each class reviewer their own username and password using
   the dashboard's private JSON accounts file. Reference that file with the
   optional `"accounts"` field in `range.json`. Keep class credentials and
   witness key files outside the repo.
6. Start the helper and restart the web service.

   ```sh
   sudo systemctl daemon-reload
   sudo systemctl enable --now firewall-auditor-helper.service
   sudo systemctl restart firewall-auditor.service
   ```

In the dashboard, run an audit, select the enrolled changes, review the exact
batch and click **Approve and apply**. Review the connection results for both
clients and the change history. Use **Restore original rules** before handing the
shared instance to another reviewer. Review expiration also resets the test
rules. A recovery error blocks further changes until an administrator compares
the active and saved policy from the VM console.
