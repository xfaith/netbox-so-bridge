# NetBox ↔ Security Onion Bridge

A lightweight bridge that correlates **NetBox authoritative inventory** with **Security Onion / Zeek passive observations**.

The project currently provides two primary functions:

1. Generate Security Onion `ip-descriptions.csv` mappings from NetBox inventory enriched with passive Security Onion observations.
2. Generate topology and monitoring-coverage reports showing which known assets are observed, which are not observed, which monitoring sensor/TAP saw them, and which source/destination relationships are active.

> **Status:** keep `DRY_RUN=true` until the generated mappings and reports have been reviewed. With dry-run enabled, the bridge reads NetBox and Security Onion and writes local output files, but does not publish mappings back to Security Onion.

---

## Architecture

```text
                 NetBox
          authoritative inventory
                    |
                    v
          netbox-so-bridge
             Docker container
            /             \
           /               \
          v                 v
 Security Onion / Zeek    Local reports
 passive observations     /data/topology
          |
          +-- optional publish --> /nsm/custom-mappings/ip-descriptions.csv
```

NetBox remains the source of truth. Security Onion provides observed hostnames, services, MAC information where available, traffic relationships, and sensor visibility.

---

## Repository Layout

```text
netbox-so-bridge/
├── app/
│   ├── main.py
│   ├── mappings.py
│   ├── netbox.py
│   ├── security_onion.py
│   ├── so_reader.py
│   ├── coverage.py
│   ├── topology_config.py
│   ├── topology_export.py
│   ├── topology_models.py
│   ├── topology_phase.py
│   ├── topology_scope.py
│   ├── topology_state.py
│   └── traffic_reader.py
├── config/
│   └── sensors.yaml
├── data/
│   └── topology/
├── security_onion/
│   ├── netbox-so-observe.py
│   ├── netbox-so-topology
│   ├── update-so-ip-mappings.sh
│   └── sudoers.additions
├── .env.example
├── .gitignore
├── .dockerignore
├── Dockerfile
├── docker-compose.yml
└── requirements.txt
```

`data/` and `data/topology/` are tracked only with `.gitkeep` placeholders. Generated CSV/JSON/state files should **not** be committed.

---

## Requirements

### Bridge host

- Linux host with Docker and Docker Compose
- Network access to NetBox
- SSH access to Security Onion
- NetBox API token with read access to the required inventory/IP objects

### Security Onion

- Zeek logs available under `/nsm/zeek/logs/current`
- A dedicated SSH account such as `netbox-sync`
- The helper scripts from this repository installed under `/usr/local/sbin`

---

# Installation

## 1. Clone the repository

```bash
git clone https://github.com/xfaith/netbox-so-bridge.git
cd netbox-so-bridge
```

## 2. Create runtime directories

```bash
mkdir -p data/topology .ssh-container
```

The container runs as UID/GID `10001`, so the writable data directory must be writable by that account:

```bash
sudo chown -R 10001:10001 data
```

`config/` may remain root-owned/read-only as long as the files are world-readable:

```bash
sudo chown -R root:root config
sudo chmod 755 config
sudo chmod 644 config/sensors.yaml
```

## 3. Create `.env`

```bash
cp .env.example .env
```

Edit `.env` and set at minimum:

```text
NETBOX_URL=http://NETBOX_HOST:8000
NETBOX_TOKEN=REPLACE_WITH_NETBOX_TOKEN
SO_HOST=SECURITY_ONION_HOST
SO_USER=netbox-sync
DRY_RUN=true
```

Do **not** commit `.env`.

---

# Security Onion Setup

## 4. Create the dedicated SSH account

On the Security Onion host:

```bash
sudo useradd --create-home --shell /bin/bash netbox-sync
sudo mkdir -p /home/netbox-sync/.ssh
sudo chown -R netbox-sync:netbox-sync /home/netbox-sync/.ssh
sudo chmod 700 /home/netbox-sync/.ssh
```

If the account already exists, skip the `useradd` step.

## 5. Create an SSH key for the bridge

On the bridge host, create a host-owned key first:

```bash
mkdir -p .ssh
ssh-keygen -t ed25519 -f .ssh/id_ed25519 -N ""
chmod 600 .ssh/id_ed25519
```

Install the public key on Security Onion:

```bash
ssh-copy-id -i .ssh/id_ed25519.pub netbox-sync@SECURITY_ONION_HOST
```

Test it:

```bash
ssh -i .ssh/id_ed25519 netbox-sync@SECURITY_ONION_HOST 'whoami'
```

Expected output:

```text
netbox-sync
```

The container runs as UID `10001`, so create a dedicated container-readable copy:

```bash
cp .ssh/id_ed25519 .ssh-container/id_ed25519
sudo chown 10001:10001 .ssh-container/id_ed25519
sudo chmod 600 .ssh-container/id_ed25519
sudo chown 10001:10001 .ssh-container
sudo chmod 700 .ssh-container
```

The private key directory is ignored by Git and must never be committed.

---

## 6. Install Security Onion helper scripts

Copy the repository helper files to the Security Onion host.

Install the passive observation helper as:

```bash
sudo cp security_onion/netbox-so-observe.py /usr/local/sbin/netbox-so-observe
```

Install the topology helper:

```bash
sudo cp security_onion/netbox-so-topology /usr/local/sbin/netbox-so-topology
```

Install the mapping publisher helper:

```bash
sudo cp security_onion/update-so-ip-mappings.sh /usr/local/sbin/update-so-ip-mappings.sh
```

Set ownership and permissions:

```bash
sudo chown root:root \
  /usr/local/sbin/netbox-so-observe \
  /usr/local/sbin/netbox-so-topology \
  /usr/local/sbin/update-so-ip-mappings.sh

sudo chmod 750 \
  /usr/local/sbin/netbox-so-observe \
  /usr/local/sbin/netbox-so-topology \
  /usr/local/sbin/update-so-ip-mappings.sh
```

---

## 7. Configure sudoers

Use `visudo`; do not edit `/etc/sudoers` directly.

```bash
sudo visudo -f /etc/sudoers.d/netbox-so-bridge
```

Add:

```text
netbox-sync ALL=(root) NOPASSWD: /usr/local/sbin/netbox-so-observe --hours *
netbox-sync ALL=(root) NOPASSWD: /usr/local/sbin/netbox-so-topology --hours *
netbox-sync ALL=(root) NOPASSWD: /usr/local/sbin/update-so-ip-mappings.sh /home/netbox-sync/ip-descriptions.csv.tmp
```

Validate the configuration:

```bash
sudo visudo -c
sudo -l -U netbox-sync
```

---

## 8. Test Security Onion helpers

Passive observations:

```bash
sudo -u netbox-sync sudo -n /usr/local/sbin/netbox-so-observe --hours 24 | jq '.asset_count'
```

Topology collection:

```bash
sudo -u netbox-sync sudo -n /usr/local/sbin/netbox-so-topology --hours 24 | jq '.observation_count, .edge_count'
```

The second command may return a large edge count; that is normal. The bridge aggregates and reduces the data for analyst-facing reports.

---

# Sensor / TAP Configuration

Edit `config/sensors.yaml`.

Example:

```yaml
sensors:
  - name: so-home
    tap: tap-home
    host: 192.168.50.229
    port: 22
    user: netbox-sync
    ssh_key: /home/bridge/.ssh/id_ed25519
    helper: /usr/local/sbin/netbox-so-topology
    expected_networks:
      - 192.168.50.0/24
```

`expected_networks` means the sensor/TAP is expected to have visibility into that subnet. Only configure a network if that expectation is actually true, otherwise partial-coverage/blind-spot results will be misleading.

Additional sensors/TAPs can be added as additional entries.

---

# Build and Run

Validate the Compose configuration:

```bash
docker compose config
```

Build and start:

```bash
sudo docker compose down
sudo docker compose build --no-cache
sudo docker compose up -d
```

Follow logs:

```bash
sudo docker compose logs -f netbox-so-bridge
```

A healthy dry-run should show messages similar to:

```text
Retrieved N IP addresses from NetBox
Retrieved N observed assets from Security Onion
Generated N Security Onion mappings
Running topology and sensor coverage phase
Topology sensor ... returned ... observations and ... edges
Topology coverage summary: ...
DRY_RUN enabled; not publishing to Security Onion
```

---

# Generated Outputs

## Mapping file

```text
data/ip-descriptions.csv
```

This is the candidate Security Onion mapping file.

## Topology / coverage reports

```text
data/topology/
├── asset-coverage.csv
├── blind-spots.csv
├── unknown-internal-assets.csv
├── external-destinations.csv
├── sensor-coverage.csv
├── traffic-edges-full.csv
├── traffic-edges-summary.csv
├── topology-full.json
├── topology-visual.json
└── topology-state.json
```

### Report purpose

- `asset-coverage.csv` — internal NetBox-known assets and observation status
- `blind-spots.csv` — known internal assets not observed in the current window
- `unknown-internal-assets.csv` — observed internal IPs not represented in NetBox
- `external-destinations.csv` — external IP destinations separated from internal unknown assets
- `sensor-coverage.csv` — per-sensor/TAP coverage and overlap
- `traffic-edges-full.csv` — detailed observed source/destination/service relationships
- `traffic-edges-summary.csv` — human-readable source/destination aggregation
- `topology-full.json` — full graph backend dataset
- `topology-visual.json` — reduced graph suitable for visualization
- `topology-state.json` — persisted historical first/last seen state

IPv6 topology reporting is disabled by default with:

```text
TOPOLOGY_INCLUDE_IPV6=false
```

---

# Dry Run vs Publishing

Default / recommended while testing:

```text
DRY_RUN=true
```

In this mode the bridge performs collection and report generation but does not write the mapping file into Security Onion.

After reviewing the generated `data/ip-descriptions.csv` and validating the publisher helper, set:

```text
DRY_RUN=false
```

The bridge will then upload the temporary file to:

```text
/home/netbox-sync/ip-descriptions.csv.tmp
```

and invoke:

```text
/usr/local/sbin/update-so-ip-mappings.sh
```

which installs the validated mapping into:

```text
/nsm/custom-mappings/ip-descriptions.csv
```

---

# Useful Tests

Verify the container can read the sensor configuration:

```bash
docker compose exec netbox-so-bridge cat /config/sensors.yaml
```

Verify environment paths:

```bash
docker compose exec netbox-so-bridge sh -c 'echo "$TOPOLOGY_OUTPUT_DIR"'
```

Test topology collection from inside the container:

```bash
docker compose exec netbox-so-bridge \
  ssh -i /home/bridge/.ssh/id_ed25519 \
  netbox-sync@SECURITY_ONION_HOST \
  'sudo -n /usr/local/sbin/netbox-so-topology --hours 24 | jq ".observation_count, .edge_count"'
```

---

# Security Notes

- Never commit `.env`, API tokens, passwords, SSH private keys, or generated topology/state data.
- Rotate any credential that has ever been committed to a public repository.
- The current SSH client code uses Paramiko `AutoAddPolicy`; pinning the Security Onion host key is recommended for a hardened deployment.
- Keep `DRY_RUN=true` until the output and Security Onion publishing helper have been validated.
- Treat NetBox as authoritative inventory and observed Security Onion data as enrichment/telemetry rather than automatically creating NetBox assets from every observation.

---

# Current Development Direction

Planned / likely enhancements include:

- MAC-aware NetBox ↔ Security Onion identity correlation
- DNS / TLS SNI / HTTP Host enrichment for external destinations
- offline ASN/provider enrichment for air-gapped deployments
- SIEM-friendly NDJSON/ECS output
- Elastic/Splunk dashboards for sensor coverage, blind spots, and communication topology
- stronger SSH host-key verification
