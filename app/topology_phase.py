import logging, os
from pathlib import Path
from coverage import aggregate_edges, build_coverage
from topology_config import load_sensors
from topology_export import export_all
from topology_state import apply_history, load_state, save_state
from traffic_reader import SecurityOnionTrafficReader, normalize_edges

log = logging.getLogger("netbox-so-bridge.topology")

def run_topology_phase(netbox_records):
    output_dir=os.getenv("TOPOLOGY_OUTPUT_DIR","/data/topology")
    state_file=os.getenv("TOPOLOGY_STATE_FILE",f"{output_dir}/topology-state.json")
    hours=int(os.getenv("TOPOLOGY_HOURS","24"))
    Path(output_dir).mkdir(parents=True, exist_ok=True)

    sensors=load_sensors()
    payloads=[]; all_edges=[]

    for sensor in sensors:
        try:
            payload=SecurityOnionTrafficReader(sensor=sensor,hours=hours).read()
            payloads.append(payload)
            all_edges.extend(normalize_edges(payload))
        except Exception:
            log.exception("Topology collection failed for sensor %s", sensor.name)

    if not payloads:
        raise RuntimeError("No topology sensor payloads were collected")

    coverage=build_coverage(netbox_records,payloads,sensors)
    state=load_state(state_file)
    apply_history(coverage,state)
    merged_edges=aggregate_edges(all_edges)
    outputs=export_all(coverage,merged_edges,sensors,output_dir)
    save_state(state_file,coverage)

    known=[r for r in coverage.values() if r.netbox_known and r.scope=="internal"]
    summary={
        "known_internal_assets":len(known),
        "observed_known_internal_assets":len([r for r in known if r.observed]),
        "unobserved_known_internal_assets":len([r for r in known if not r.observed]),
        "multi_sensor_assets":len([r for r in known if r.observed and r.sensor_count>1]),
        "unknown_internal_assets":len([r for r in coverage.values() if r.observed and not r.netbox_known and r.scope=="internal"]),
        "traffic_edges":len(merged_edges),
        "outputs":outputs,
    }
    log.info("Topology coverage summary: %s",summary)
    return summary
