import csv, json, os
from pathlib import Path
from topology_scope import ip_sort_key

def safe_name(coverage, ip):
    row = coverage.get(ip)
    return row.name if row else ip

def write_csv(path, header, rows):
    with Path(path).open("w", newline="", encoding="utf-8") as h:
        w = csv.writer(h); w.writerow(header); w.writerows(rows)

def export_all(coverage, edges, sensors, output_dir):
    out = Path(output_dir); out.mkdir(parents=True, exist_ok=True)

    internal_known = [r for r in coverage.values() if r.netbox_known and r.scope=="internal"]
    internal_known.sort(key=lambda r: ip_sort_key(r.ip))

    write_csv(out/"asset-coverage.csv",
        ["IP","Name","Scope","ObservedInWindow","CoverageStatus","ObservedBy","ExpectedBy","MissingExpectedSensors","SensorCount","FirstSeenInWindow","LastSeenInWindow","HistoricalFirstSeen","HistoricalLastSeen"],
        [[r.ip,r.name,r.scope,r.observed,r.coverage_status,";".join(sorted(r.observed_by)),";".join(sorted(r.expected_by)),";".join(sorted(r.missing_expected_sensors)),r.sensor_count,r.first_seen,r.last_seen,r.historical_first_seen,r.historical_last_seen] for r in internal_known])

    blind = [r for r in internal_known if not r.observed]
    write_csv(out/"blind-spots.csv",
        ["IP","Name","Status","ExpectedBy","HistoricalLastSeen"],
        [[r.ip,r.name,r.coverage_status,";".join(sorted(r.expected_by)),r.historical_last_seen] for r in blind])

    unknown = [r for r in coverage.values() if r.observed and not r.netbox_known and r.scope=="internal"]
    unknown.sort(key=lambda r: ip_sort_key(r.ip))
    write_csv(out/"unknown-internal-assets.csv",
        ["IP","ObservedName","ObservedBy","SensorCount","FirstSeenInWindow","LastSeenInWindow","HistoricalFirstSeen","HistoricalLastSeen"],
        [[r.ip,r.name,";".join(sorted(r.observed_by)),r.sensor_count,r.first_seen,r.last_seen,r.historical_first_seen,r.historical_last_seen] for r in unknown])

    sensor_rows=[]
    for s in sorted(sensors,key=lambda x:x.name):
        observed=[r for r in internal_known if s.name in r.observed_by]
        unique=[r for r in observed if len(r.observed_by)==1]
        overlap=[r for r in observed if len(r.observed_by)>1]
        expected=[r for r in internal_known if s.name in r.expected_by]
        denom=len(expected) if expected else len(internal_known)
        pct=round((len(observed)/denom)*100,1) if denom else 0.0
        sensor_rows.append([s.name,s.host,s.tap,len(internal_known),len(observed),len(unique),len(overlap),len(expected),pct])
    write_csv(out/"sensor-coverage.csv",
        ["SensorName","SensorIP","TAP","InternalKnownAssets","InternalAssetsObserved","UniqueInternalAssets","MultiSensorOverlap","ExpectedAssets","CoveragePercent"],
        sensor_rows)

    full_rows=[]
    for e in edges:
        summary=f"{safe_name(coverage,e['source_ip'])} -> {safe_name(coverage,e['destination_ip'])} | {e['service'] or 'unknown-service'} {e['destination_port'] or ''}/{e['protocol'] or ''} | {e['connections']} connections | {e['bytes_total']} bytes"
        full_rows.append([summary,e["relationship_type"],e["source_ip"],safe_name(coverage,e["source_ip"]),e["source_scope"],e["destination_ip"],safe_name(coverage,e["destination_ip"]),e["destination_scope"],e["destination_port"],e["protocol"],e["service"],e["connections"],e["bytes_total"],";".join(e["sensors"]),";".join(e["taps"]),e["sensor_count"],e["first_seen"],e["last_seen"]])
    write_csv(out/"traffic-edges-full.csv",
        ["PathSummary","RelationshipType","SourceIP","SourceName","SourceScope","DestinationIP","DestinationName","DestinationScope","DestinationPort","Protocol","Service","Connections","BytesTotal","ObservedBy","TAPs","SensorCount","FirstSeen","LastSeen"],
        full_rows)

    pair={}
    for e in edges:
        k=(e["source_ip"],e["destination_ip"])
        g=pair.setdefault(k,{"connections":0,"bytes":0,"services":set(),"ports":set(),"sensors":set(),"taps":set(),"rel":e["relationship_type"]})
        g["connections"]+=e["connections"]; g["bytes"]+=e["bytes_total"]
        if e["service"]: g["services"].add(e["service"])
        if e["destination_port"]: g["ports"].add(str(e["destination_port"]))
        g["sensors"].update(e["sensors"]); g["taps"].update(e["taps"])
    rows=[]
    for (src,dst),g in sorted(pair.items(), key=lambda kv:(kv[1]["connections"],kv[1]["bytes"]), reverse=True):
        rows.append([f"{safe_name(coverage,src)} -> {safe_name(coverage,dst)} | {g['connections']} connections | {g['bytes']} bytes",g["rel"],src,safe_name(coverage,src),dst,safe_name(coverage,dst),g["connections"],g["bytes"],";".join(sorted(g["services"])),";".join(sorted(g["ports"])),";".join(sorted(g["sensors"])),";".join(sorted(g["taps"]))])
    write_csv(out/"traffic-edges-summary.csv",
        ["PathSummary","RelationshipType","SourceIP","SourceName","DestinationIP","DestinationName","Connections","BytesTotal","Services","Ports","ObservedBy","TAPs"],rows)

    ext={}
    for e in edges:
        if e["relationship_type"]!="internal_external": continue
        g=ext.setdefault(e["destination_ip"],{"sources":set(),"connections":0,"bytes":0,"services":set(),"sensors":set()})
        g["sources"].add(e["source_ip"]); g["connections"]+=e["connections"]; g["bytes"]+=e["bytes_total"]
        if e["service"]: g["services"].add(e["service"])
        g["sensors"].update(e["sensors"])
    write_csv(out/"external-destinations.csv",
        ["DestinationIP","InternalSourceCount","InternalSources","Connections","BytesTotal","Services","ObservedBy"],
        [[ip,len(g["sources"]),";".join(sorted(g["sources"],key=ip_sort_key)),g["connections"],g["bytes"],";".join(sorted(g["services"])),";".join(sorted(g["sensors"]))] for ip,g in sorted(ext.items(), key=lambda kv: ip_sort_key(kv[0]))])

    def graph(selected):
        ips=set()
        for e in selected: ips.update((e["source_ip"],e["destination_ip"]))
        nodes=[]
        for ip in sorted(ips,key=ip_sort_key):
            r=coverage.get(ip)
            nodes.append({"id":ip,"label":r.name if r else ip,"ip":ip,"scope":r.scope if r else "external","netbox_known":r.netbox_known if r else False,"coverage_status":r.coverage_status if r else "external_or_uninventoried"})
        gedges=[{"id":f"edge-{i}","source":e["source_ip"],"target":e["destination_ip"],"relationship_type":e["relationship_type"],"connections":e["connections"],"bytes_total":e["bytes_total"],"service":e["service"],"destination_port":e["destination_port"],"sensors":e["sensors"],"taps":e["taps"]} for i,e in enumerate(selected,1)]
        return {"nodes":nodes,"edges":gedges}

    (out/"topology-full.json").write_text(json.dumps(graph(edges),indent=2),encoding="utf-8")

    min_conn=int(os.getenv("TOPOLOGY_VISUAL_MIN_CONNECTIONS","5"))
    min_bytes=int(os.getenv("TOPOLOGY_VISUAL_MIN_BYTES","51200"))
    max_edges=int(os.getenv("TOPOLOGY_VISUAL_MAX_EDGES","1000"))
    visual=[e for e in edges if e["relationship_type"]=="internal_internal" or (e["relationship_type"]=="internal_external" and (e["connections"]>=min_conn or e["bytes_total"]>=min_bytes))]
    visual.sort(key=lambda e:(e["connections"],e["bytes_total"]), reverse=True)
    visual=visual[:max_edges]
    (out/"topology-visual.json").write_text(json.dumps(graph(visual),indent=2),encoding="utf-8")

    return {name:str(out/name) for name in [
        "asset-coverage.csv","blind-spots.csv","unknown-internal-assets.csv",
        "external-destinations.csv","sensor-coverage.csv","traffic-edges-full.csv",
        "traffic-edges-summary.csv","topology-full.json","topology-visual.json"
    ]}
