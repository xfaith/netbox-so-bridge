import ipaddress
import os
from pathlib import Path
import yaml
from topology_models import SensorDefinition


def load_sensors(path=None):
    path = path or os.getenv("TOPOLOGY_SENSOR_CONFIG", "/config/sensors.yaml")
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"Topology sensor configuration not found: {path}")
    data = yaml.safe_load(p.read_text()) or {}
    sensors = []
    for item in data.get("sensors", []):
        sensors.append(SensorDefinition(
            name=str(item["name"]),
            host=str(item["host"]),
            port=int(item.get("port", 22)),
            user=str(item.get("user", "netbox-sync")),
            ssh_key=str(item.get("ssh_key", os.getenv("SO_SSH_KEY", "/home/bridge/.ssh/id_ed25519"))),
            helper=str(item.get("helper", "/usr/local/sbin/netbox-so-topology")),
            tap=str(item.get("tap", item.get("name", ""))),
            expected_networks=[str(v) for v in item.get("expected_networks", [])],
        ))
    if not sensors:
        raise ValueError("No sensors configured in sensors.yaml")
    return sensors


def expected_sensors_for_ip(ip, sensors):
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return set()
    out = set()
    for sensor in sensors:
        for network in sensor.expected_networks:
            try:
                if addr in ipaddress.ip_network(network, strict=False):
                    out.add(sensor.name)
                    break
            except ValueError:
                pass
    return out
