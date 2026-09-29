#!/usr/bin/env bash
set -euo pipefail

SOURCE_FILE="${1:-}"
DEST_FILE="/nsm/custom-mappings/ip-descriptions.csv"
DEST_DIR="$(dirname "$DEST_FILE")"
TMP_FILE="${DEST_FILE}.new"
BACKUP_FILE="${DEST_FILE}.bak"

log() {
  logger -t netbox-so-sync "$*"
  echo "$*"
}

if [[ -z "$SOURCE_FILE" ]]; then
  echo "Usage: $0 /path/to/ip-descriptions.csv"
  exit 2
fi

if [[ ! -f "$SOURCE_FILE" ]]; then
  log "ERROR: Source file does not exist: $SOURCE_FILE"
  exit 3
fi

if [[ ! -s "$SOURCE_FILE" ]]; then
  log "ERROR: Source file is empty: $SOURCE_FILE"
  exit 4
fi

HEADER="$(head -n 1 "$SOURCE_FILE" | tr -d '\r')"

if [[ "$HEADER" != "IP,Description" ]]; then
  log "ERROR: Invalid CSV header: $HEADER"
  exit 5
fi

LINE_COUNT="$(wc -l < "$SOURCE_FILE")"

if (( LINE_COUNT < 2 )); then
  log "ERROR: CSV contains no mappings"
  exit 6
fi

python3 - "$SOURCE_FILE" <<'PY'
import csv
import ipaddress
import sys

path = sys.argv[1]

with open(path, newline="", encoding="utf-8") as f:
    reader = csv.DictReader(f)

    if reader.fieldnames != ["IP", "Description"]:
        raise SystemExit("Invalid CSV columns")

    count = 0

    for row in reader:
        ip = (row.get("IP") or "").strip()
        desc = (row.get("Description") or "").strip()

        if not ip:
            raise SystemExit("Blank IP address found")

        try:
            ipaddress.ip_address(ip)
        except ValueError:
            raise SystemExit(f"Invalid IP address: {ip}")

        if not desc:
            raise SystemExit(f"Blank description for {ip}")

        count += 1

    if count == 0:
        raise SystemExit("No valid mappings found")
PY

mkdir -p "$DEST_DIR"

if [[ -f "$DEST_FILE" ]]; then
  cp -p "$DEST_FILE" "$BACKUP_FILE"
fi

install -m 0644 "$SOURCE_FILE" "$TMP_FILE"
mv -f "$TMP_FILE" "$DEST_FILE"

log "Successfully installed $((LINE_COUNT - 1)) IP mappings to $DEST_FILE"