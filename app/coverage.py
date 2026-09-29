import ipaddress
from collections import defaultdict
from topology_config import expected_sensors_for_ip
from topology_models import AssetCoverage
from topology_scope import classify_ip, reportable_ip

def strip_prefix(address):
    try:
        return str(ipaddress.ip_interface(address).ip)
    except ValueError:
        return ""

def netbox_name(record):
    assigned = record.get("assigned_object") or {}
    if isinstance(assigned, dict):
        for key in ("device","virtual_machine"):
            obj = assigned.get(key)
            if isinstance(obj, dict):
                value = obj.get("name") or obj.get("display")
                if value:
                    return str(value).strip()
    for field in ("dns_name","description"):
        value = str(record.get(field) or "").strip()
        if value:
            return value.rstrip(".")
    return ""

def _earliest(values):
    values = [v for v in values if v]
    return min(values) if values else ""

def _latest(values):
    values = [v for v in values if v]
    return max(values) if values else ""

def build_coverage(netbox_records, sensor_payloads, sensors):
    coverage = {}
    first_seen = defaultdict(list)
    last_seen = defaultdict(list)

    for record in netbox_records:
        ip = strip_prefix(str(record.get("address","")))
        if not ip or not reportable_ip(ip):
            continue
        coverage[ip] = AssetCoverage(
            ip=ip, name=netbox_name(record) or ip, netbox_known=True,
            observed=False, scope=classify_ip(ip),
            expected_by=expected_sensors_for_ip(ip, sensors),
        )

    for payload in sensor_payloads:
        sensor = str(payload.get("sensor",""))
        for item in payload.get("observations",[]):
            ip = str(item.get("ip","")).strip()
            if not ip or not reportable_ip(ip):
                continue
            try:
                ipaddress.ip_address(ip)
            except ValueError:
                continue
            if ip not in coverage:
                coverage[ip] = AssetCoverage(
                    ip=ip, name=str(item.get("hostname") or ip),
                    netbox_known=False, observed=True, scope=classify_ip(ip),
                    expected_by=expected_sensors_for_ip(ip, sensors),
                )
            row = coverage[ip]
            row.observed = True
            row.observed_by.add(sensor)
            if item.get("first_seen"):
                first_seen[ip].append(str(item["first_seen"]))
            if item.get("last_seen"):
                last_seen[ip].append(str(item["last_seen"]))

    for ip,row in coverage.items():
        row.first_seen = _earliest(first_seen[ip])
        row.last_seen = _latest(last_seen[ip])
    return coverage

def aggregate_edges(edges):
    grouped = {}
    for edge in edges:
        if not reportable_ip(edge.source_ip) or not reportable_ip(edge.destination_ip):
            continue
        key = (edge.source_ip, edge.destination_ip, edge.destination_port, edge.protocol, edge.service)
        if key not in grouped:
            grouped[key] = {
                "source_ip":edge.source_ip,"destination_ip":edge.destination_ip,
                "destination_port":edge.destination_port,"protocol":edge.protocol,
                "service":edge.service,"connections":0,"bytes_total":0,
                "sensors":set(),"taps":set(),"first_seen":[],"last_seen":[]
            }
        g = grouped[key]
        g["connections"] += edge.connections
        g["bytes_total"] += edge.bytes_total
        if edge.sensor: g["sensors"].add(edge.sensor)
        if edge.tap: g["taps"].add(edge.tap)
        if edge.first_seen: g["first_seen"].append(edge.first_seen)
        if edge.last_seen: g["last_seen"].append(edge.last_seen)

    out = []
    for g in grouped.values():
        ss, ds = classify_ip(g["source_ip"]), classify_ip(g["destination_ip"])
        if ss=="internal" and ds=="internal": rel="internal_internal"
        elif ss=="internal" and ds=="external": rel="internal_external"
        elif ss=="external" and ds=="internal": rel="external_internal"
        elif "multicast" in (ss,ds): rel="multicast"
        else: rel=f"{ss}_{ds}"
        out.append({
            **{k:v for k,v in g.items() if k not in ("sensors","taps","first_seen","last_seen")},
            "source_scope":ss,"destination_scope":ds,"relationship_type":rel,
            "sensors":sorted(g["sensors"]),"taps":sorted(g["taps"]),
            "sensor_count":len(g["sensors"]),
            "first_seen":_earliest(g["first_seen"]),"last_seen":_latest(g["last_seen"]),
        })
    return out
