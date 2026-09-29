#!/usr/bin/env python3

import argparse
import gzip
import ipaddress
import json
import os
import time
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path


ZEEK_ROOT = Path("/nsm/zeek/logs/current")

INTERNAL_NETWORKS = [
    ipaddress.ip_network("192.168.50.0/24")
]


def parse_args():
    parser = argparse.ArgumentParser(
        description="Export passive Security Onion/Zeek asset observations."
    )

    parser.add_argument(
        "--hours",
        type=int,
        default=24,
        help="Observation window in hours (1-168)."
    )

    args = parser.parse_args()

    if not 1 <= args.hours <= 168:
        parser.error("--hours must be between 1 and 168")

    return args


def open_log(path):
    if str(path).endswith(".gz"):
        return gzip.open(
            path,
            "rt",
            encoding="utf-8",
            errors="replace"
        )

    return open(
        path,
        "r",
        encoding="utf-8",
        errors="replace"
    )


def valid_ip(value):
    if not value or value == "-":
        return False

    try:
        ipaddress.ip_address(value)
        return True

    except ValueError:
        return False


def is_internal_ip(value):
    if not valid_ip(value):
        return False

    ip = ipaddress.ip_address(value)

    return any(
        ip in network
        for network in INTERNAL_NETWORKS
    )


def parse_zeek_file(path):
    """
    Supports both Zeek JSON logs and traditional TSV Zeek logs.
    """

    fields = None
    separator = "\t"

    try:
        with open_log(path) as f:

            for raw in f:
                line = raw.rstrip("\n")

                if not line:
                    continue

                #
                # Zeek JSON
                #
                if line.startswith("{"):

                    try:
                        yield json.loads(line)

                    except json.JSONDecodeError:
                        continue

                    continue

                #
                # Traditional Zeek log format
                #
                if line.startswith("#separator"):

                    parts = line.split(" ", 1)

                    if len(parts) == 2:
                        encoded = parts[1]

                        try:
                            separator = bytes(
                                encoded,
                                "utf-8"
                            ).decode(
                                "unicode_escape"
                            )

                        except Exception:
                            separator = "\t"

                    continue

                if line.startswith("#fields"):

                    parts = line.split(separator)

                    fields = parts[1:]

                    continue

                if line.startswith("#"):
                    continue

                if not fields:
                    continue

                values = line.split(separator)

                if len(values) != len(fields):
                    continue

                yield dict(
                    zip(
                        fields,
                        values
                    )
                )

    except (
        PermissionError,
        FileNotFoundError
    ):
        return


def record_timestamp(record):
    value = record.get("ts")

    if value is None:
        return None

    try:
        return float(value)

    except (
        ValueError,
        TypeError
    ):
        return None


def find_logs(prefix):
    """
    Only read current Zeek logs.
    """

    path = ZEEK_ROOT / f"{prefix}.log"

    if path.exists():
        return [path]

    return []


def add_seen(asset, timestamp):
    if timestamp is None:
        return

    current_first = asset.get(
        "first_seen"
    )

    current_last = asset.get(
        "last_seen"
    )

    if (
        current_first is None
        or timestamp < current_first
    ):
        asset["first_seen"] = timestamp

    if (
        current_last is None
        or timestamp > current_last
    ):
        asset["last_seen"] = timestamp


def normalize_list(value):
    if value is None or value == "-":
        return []

    if isinstance(value, list):
        return value

    if isinstance(value, str):
        value = value.strip()

        if (
            value.startswith("[")
            and value.endswith("]")
        ):
            try:
                parsed = json.loads(value)

                if isinstance(parsed, list):
                    return parsed

            except json.JSONDecodeError:
                pass

        return [
            item.strip()
            for item in value.split(",")
            if item.strip()
        ]

    return []


def add_hostname(asset, hostname):
    if not hostname or hostname == "-":
        return

    hostname = str(hostname).strip().rstrip(".")

    if hostname:
        asset["hostnames"].add(
            hostname
        )


def add_mac(asset, mac):
    if not mac or mac == "-":
        return

    mac = str(mac).strip().lower()

    if mac:
        asset["macs"].add(
            mac
        )


def add_service(
    asset,
    port,
    protocol="tcp",
    service=None
):
    if not port or port == "-":
        return

    protocol = (
        str(protocol).strip().lower()
        if protocol
        else "tcp"
    )

    if service and service != "-":

        value = (
            f"{service} "
            f"{port}/{protocol}"
        )

    else:

        value = (
            f"{port}/{protocol}"
        )

    asset["services"].add(
        value
    )


def main():
    args = parse_args()

    cutoff = (
        time.time()
        - (args.hours * 3600)
    )

    assets = defaultdict(
        lambda: {
            "hostnames": set(),
            "macs": set(),
            "services": set(),
            "sources": set(),
            "first_seen": None,
            "last_seen": None,
        }
    )

    #
    # DNS
    #
    for path in find_logs("dns"):

        for record in parse_zeek_file(
            path
        ):

            ts = record_timestamp(
                record
            )

            if ts and ts < cutoff:
                continue

            query = (
                record.get("query")
                or ""
            ).rstrip(".")

            answers = normalize_list(
                record.get("answers")
            )

            for answer in answers:

                answer = (
                    str(answer)
                    .strip()
                    .rstrip(".")
                )

                if not is_internal_ip(
                    answer
                ):
                    continue

                asset = assets[answer]

                if query:
                    add_hostname(
                        asset,
                        query
                    )

                asset["sources"].add(
                    "dns"
                )

                add_seen(
                    asset,
                    ts
                )

    #
    # DHCP
    #
    for path in find_logs("dhcp"):

        for record in parse_zeek_file(
            path
        ):

            ts = record_timestamp(
                record
            )

            if ts and ts < cutoff:
                continue

            ip = (
                record.get(
                    "assigned_ip"
                )
                or record.get(
                    "assigned_addr"
                )
                or record.get(
                    "client_addr"
                )
                or record.get(
                    "requested_addr"
                )
            )

            if not is_internal_ip(ip):
                continue

            asset = assets[ip]

            hostname = (
                record.get("host_name")
                or record.get(
                    "client_fqdn"
                )
            )

            add_hostname(
                asset,
                hostname
            )

            mac = record.get("mac")

            add_mac(
                asset,
                mac
            )

            asset["sources"].add(
                "dhcp"
            )

            add_seen(
                asset,
                ts
            )

    #
    # known_hosts
    #
    for path in find_logs(
        "known_hosts"
    ):

        for record in parse_zeek_file(
            path
        ):

            ts = record_timestamp(
                record
            )

            if ts and ts < cutoff:
                continue

            ip = (
                record.get("host")
                or record.get(
                    "host_ip"
                )
            )

            if not is_internal_ip(ip):
                continue

            asset = assets[ip]

            asset["sources"].add(
                "known_hosts"
            )

            add_seen(
                asset,
                ts
            )

    #
    # known_services
    #
    for path in find_logs(
        "known_services"
    ):

        for record in parse_zeek_file(
            path
        ):

            ts = record_timestamp(
                record
            )

            if ts and ts < cutoff:
                continue

            ip = record.get("host")

            if not is_internal_ip(ip):
                continue

            asset = assets[ip]

            port = (
                record.get("port_num")
                or record.get("port")
            )

            proto = (
                record.get("port_proto")
                or record.get("proto")
                or "tcp"
            )

            service = (
                record.get("service")
            )

            add_service(
                asset,
                port,
                proto,
                service
            )

            asset["sources"].add(
                "known_services"
            )

            add_seen(
                asset,
                ts
            )

    #
    # conn.log
    #
    # This provides basic passive presence and
    # first/last seen information for internal hosts.
    #
    for path in find_logs("conn"):

        for record in parse_zeek_file(
            path
        ):

            ts = record_timestamp(
                record
            )

            if ts and ts < cutoff:
                continue

            src = (
                record.get("id.orig_h")
                or record.get("source.ip")
            )

            dst = (
                record.get("id.resp_h")
                or record.get(
                    "destination.ip"
                )
            )

            if is_internal_ip(src):

                asset = assets[src]

                asset["sources"].add(
                    "conn"
                )

                add_seen(
                    asset,
                    ts
                )

            if is_internal_ip(dst):

                asset = assets[dst]

                asset["sources"].add(
                    "conn"
                )

                add_seen(
                    asset,
                    ts
                )

    #
    # ssl.log
    #
    # Useful for internal service certificates /
    # server names when present.
    #
    for path in find_logs("ssl"):

        for record in parse_zeek_file(
            path
        ):

            ts = record_timestamp(
                record
            )

            if ts and ts < cutoff:
                continue

            src = (
                record.get("id.orig_h")
            )

            dst = (
                record.get("id.resp_h")
            )

            server_name = (
                record.get(
                    "server_name"
                )
            )

            if (
                is_internal_ip(dst)
                and server_name
                and server_name != "-"
            ):

                asset = assets[dst]

                add_hostname(
                    asset,
                    server_name
                )

                asset["sources"].add(
                    "ssl"
                )

                add_seen(
                    asset,
                    ts
                )

    #
    # http.log
    #
    # HTTP Host headers can reveal useful local
    # application/device names.
    #
    for path in find_logs("http"):

        for record in parse_zeek_file(
            path
        ):

            ts = record_timestamp(
                record
            )

            if ts and ts < cutoff:
                continue

            dst = (
                record.get("id.resp_h")
            )

            host = record.get("host")

            if (
                is_internal_ip(dst)
                and host
                and host != "-"
            ):

                asset = assets[dst]

                add_hostname(
                    asset,
                    host
                )

                asset["sources"].add(
                    "http"
                )

                add_seen(
                    asset,
                    ts
                )

    #
    # Convert sets to sorted lists
    #
    output_assets = {}

    for ip, data in assets.items():

        output_assets[ip] = {
            "hostnames": sorted(
                data["hostnames"]
            ),

            "macs": sorted(
                data["macs"]
            ),

            "services": sorted(
                data["services"]
            ),

            "sources": sorted(
                data["sources"]
            ),

            "first_seen":
                data["first_seen"],

            "last_seen":
                data["last_seen"],
        }

    result = {

        "generated_at":
            datetime.now(
                timezone.utc
            ).isoformat(),

        "hours":
            args.hours,

        "internal_networks": [
            str(network)
            for network
            in INTERNAL_NETWORKS
        ],

        "asset_count":
            len(output_assets),

        "assets":
            output_assets,
    }

    print(
        json.dumps(
            result,
            separators=(",", ":")
        )
    )


if __name__ == "__main__":
    main()