from dataclasses import dataclass, field
from typing import List, Set

@dataclass
class SensorDefinition:
    name: str
    host: str
    port: int = 22
    user: str = "netbox-sync"
    ssh_key: str = "/home/bridge/.ssh/id_ed25519"
    helper: str = "/usr/local/sbin/netbox-so-topology"
    tap: str = ""
    expected_networks: List[str] = field(default_factory=list)

@dataclass
class TrafficEdge:
    sensor: str
    tap: str
    source_ip: str
    destination_ip: str
    source_port: int | None = None
    destination_port: int | None = None
    protocol: str = ""
    service: str = ""
    connections: int = 0
    bytes_total: int = 0
    first_seen: str = ""
    last_seen: str = ""

@dataclass
class AssetCoverage:
    ip: str
    name: str
    netbox_known: bool
    observed: bool
    scope: str = "unknown"
    observed_by: Set[str] = field(default_factory=set)
    expected_by: Set[str] = field(default_factory=set)
    first_seen: str = ""
    last_seen: str = ""
    historical_first_seen: str = ""
    historical_last_seen: str = ""

    @property
    def sensor_count(self):
        return len(self.observed_by)

    @property
    def expected_sensor_count(self):
        return len(self.expected_by)

    @property
    def missing_expected_sensors(self):
        return self.expected_by - self.observed_by

    @property
    def coverage_status(self):
        if not self.netbox_known:
            return "unknown_observed" if self.observed else "unknown"
        if not self.observed:
            return "not_seen_in_window" if self.historical_last_seen else "never_observed"
        if self.expected_by and self.missing_expected_sensors:
            return "partial_expected_coverage"
        if self.sensor_count > 1:
            return "multi_sensor"
        return "single_sensor"
