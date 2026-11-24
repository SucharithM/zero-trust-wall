# Firewall Auditor

Firewall Auditor compares a Linux host's inbound nftables rules with an expected
access policy and suggests changes in an HTTPS dashboard. It flags unsupported
rules and ambiguous paths for manual review. The dashboard runs without firewall
privileges, and Ollama can help prioritize findings. An optional local helper
applies approved changes to enrolled nftables or UFW rules.

## Run a read-only audit

On the Linux host you want to audit, install Python 3.11+, sudo, nftables, iproute2, and OpenSSL. From the repository root, run as your regular user.

```sh
python3 run_live_audit.py
```

The launcher requests sudo to read nftables, runs an audit, and prints the local
dashboard URL, credentials, and certificate path. Trust the temporary certificate
in your test client before opening the dashboard. Use `--policy` with a JSON file
based on [the example policy](config/range.example.json) to compare rules against
your own policy. Use `--check` to exit after the audit.

## Try the HTTPS demo

The demo uses sample rules and requires Python 3.11+ and OpenSSL. From the repository root, run the following commands.

```sh
mkdir -p .local
chmod 700 .local
openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
  -subj /CN=localhost -addext 'subjectAltName=DNS:localhost,IP:127.0.0.1' \
  -keyout .local/key.pem -out .local/cert.pem
export FIREWALL_AUDIT_PASSWORD="$(openssl rand -hex 18)"
printf 'Local demo password: %s\n' "$FIREWALL_AUDIT_PASSWORD"
python3 -m firewall_auditor --demo --cert .local/cert.pem --key .local/key.pem --log .local/audit.jsonl
```

Trust `.local/cert.pem` in your test client, open `https://localhost:8443`, and sign in as `auditor` with the generated password.

## Install on Ubuntu

Use an Ubuntu host or VM with systemd, Python 3.11+, nftables, and iproute2. Run the installation commands from the repository root.

1. Create the service account and install the code, systemd units, and example policy.

   ```sh
   sudo useradd --system --user-group --no-create-home --shell /usr/sbin/nologin firewall-auditor
   sudo install -d -m 0755 /opt/firewall-auditor
   sudo cp -R firewall_auditor deploy /opt/firewall-auditor/
   sudo install -m 0644 deploy/*.service deploy/*.timer /etc/systemd/system/
   sudo install -d -o root -g firewall-auditor -m 0750 /etc/firewall-auditor
   sudo install -o root -g firewall-auditor -m 0640 config/range.example.json /etc/firewall-auditor/range.json
   ```

2. Edit `/etc/firewall-auditor/range.json`. Replace the example host label and CIDRs with your host and approved source networks for each audited TCP port.
3. Install `cert.pem` and `key.pem` in `/etc/firewall-auditor/`. Use a certificate that matches the dashboard address and has a CA trusted by clients. Set `key.pem` to `root:firewall-auditor` with mode `0640`.
4. Create `/etc/firewall-auditor/environment` owned by `root:root` with mode `0600`. Generate a password of at least 16 characters. For a shared deployment, set `AUDIT_BIND` to the host's private address and share credentials privately.

   ```dotenv
   AUDIT_BIND=127.0.0.1
   FIREWALL_AUDIT_USER=auditor
   FIREWALL_AUDIT_PASSWORD=replace-with-a-generated-password
   ```

5. Start the collector and dashboard.

   ```sh
   sudo systemctl daemon-reload
   sudo systemctl start firewall-auditor-collect.service
   sudo systemctl enable --now firewall-auditor-collect.timer firewall-auditor.service
   systemctl status firewall-auditor.service firewall-auditor-collect.timer
   ```

Open the dashboard over HTTPS on port `8443`. The collector refreshes the snapshot about every 30 seconds. The dashboard rejects snapshots older than three minutes.

### Use Ollama

- For the live launcher, add `--model` with the name of a model installed in local Ollama.
- For the demo, add `--model-url` and `--model` to the dashboard command. For systemd, set `MODEL_URL` and `MODEL_NAME` in the environment file before starting or restarting the service.

Use `http://127.0.0.1:11434` for local Ollama. The demo and systemd service also
support remote Ollama over trusted HTTPS or a loopback SSH tunnel. Set
`FIREWALL_MODEL_TOKEN` if the endpoint requires a bearer token.

## Enable approved firewall changes

Set up the Ubuntu deployment first. Keep console access available for setup and recovery. The helper runs separately from the dashboard and exposes a local Unix socket.

1. On each of two verification clients, install the `firewall_auditor` package directory under `/opt/firewall-auditor/` and create a dedicated `firewall-witness` SSH account. Use [the witness example](config/witness.example.json) to create `/etc/firewall-auditor/witness.json`, owned by root and readable by the witness account. Set the target address, the two test ports, and the client's own IPv4 address in `sources`.
2. Create a dedicated SSH key on the audited host. Verify and pin both client host keys in the helper's `known_hosts` file. Add the helper's public key to each witness account with this forced command.

   ```text
   restrict,command="cd /opt/firewall-auditor && /usr/bin/python3 -m firewall_auditor.witness" ssh-ed25519 <helper-public-key>
   ```

3. Use [the helper example](config/helper.example.json) to create
   `/etc/firewall-auditor/helper.json`, owned by root with mode `0600`. Replace the
   example addresses and set the SSH key and `known_hosts` paths. Run disposable
   TCP listeners on the two test ports, bound to the host's private IPv4 address.
   Match the expected sources in `range.json` and verify that both clients can
   connect from distinct source addresses.
4. Choose one firewall backend.

   - **nftables.** From the VM console, confirm the dedicated test table is absent before provisioning and loading it once.

     ```sh
     sudo install -d -o root -g firewall-auditor -m 0700 /var/lib/firewall-auditor-helper
     sudo env PYTHONPATH=/opt/firewall-auditor /usr/bin/python3 -m firewall_auditor.helper \
       --config /etc/firewall-auditor/helper.json --provision-nft
     sudo nft -f /var/lib/firewall-auditor-helper/managed.nft
     ```

     For persistence in personal mode, add `include "/var/lib/firewall-auditor-helper/managed.nft"` to the existing `/etc/nftables.conf`, check it with `sudo nft -c -f /etc/nftables.conf`, and enable the nftables service.
   - **UFW.** Use an active UFW configuration with `"backend": "ufw"` and `"mode": "personal"`. For each enrolled TCP port, use one IPv4 allow rule with a specific source CIDR and the comment `firewall-auditor-<port>`. Keep the test service deny-by-default for other sources.

5. Add `"helper_socket": "/run/firewall-auditor-helper/control.sock"` to `range.json`. For shared nftables reviews, set `"mode": "shared"` in the helper config and set `accounts` in `range.json` to a private JSON file mapping reviewer usernames to passwords. Keep the accounts file and SSH keys outside Git.
6. Start the helper and restart the dashboard.

   ```sh
   sudo systemctl enable --now firewall-auditor-helper.service
   sudo systemctl restart firewall-auditor.service
   ```

Run an audit, review the proposed batch, and select **Approve and apply**. Check the results from both verification clients. In shared mode, use **Restore original rules** before handing off the instance. Rules also reset when the review expires. If recovery fails, use the VM console to check active and saved rules before resuming.

## Run tests

```sh
python3 -m unittest discover -s tests -v
python3 -m tests.check_https
```

The HTTPS smoke test uses sample data on loopback. Add `--model` with an installed Ollama model to exercise the model integration. Run `python3 -m tests.check_https --help` for the other test modes.
