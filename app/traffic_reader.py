import json
import logging
import shlex
import time

import paramiko

from topology_models import (
    SensorDefinition,
    TrafficEdge,
)


log = logging.getLogger(
    "netbox-so-bridge.topology"
)


class SecurityOnionTrafficReader:
    """
    Read aggregated topology observations from a
    Security Onion sensor.

    Uses a streaming Paramiko channel so large topology
    datasets cannot deadlock waiting for SSH buffers.
    """

    def __init__(
        self,
        sensor: SensorDefinition,
        hours: int = 24,
    ):
        self.sensor = sensor
        self.hours = int(hours)

    def read(self):
        #
        # -------------------------------------------------
        # SSH key
        # -------------------------------------------------
        #

        key = (
            paramiko.Ed25519Key
            .from_private_key_file(
                self.sensor.ssh_key
            )
        )

        client = paramiko.SSHClient()

        client.set_missing_host_key_policy(
            paramiko.AutoAddPolicy()
        )

        log.info(
            "Connecting to topology sensor %s at %s",
            self.sensor.name,
            self.sensor.host,
        )

        #
        # -------------------------------------------------
        # SSH connection
        # -------------------------------------------------
        #

        client.connect(
            hostname=self.sensor.host,
            port=self.sensor.port,
            username=self.sensor.user,
            pkey=key,
            timeout=20,
            banner_timeout=20,
            auth_timeout=20,
        )

        helper = shlex.quote(
            self.sensor.helper
        )

        command = (
            f"sudo -n {helper} "
            f"--hours {self.hours}"
        )

        log.info(
            "Reading topology from "
            "sensor=%s tap=%s",
            self.sensor.name,
            self.sensor.tap,
        )

        log.info(
            "Executing topology command: %s",
            command,
        )

        channel = None

        try:
            transport = (
                client.get_transport()
            )

            if (
                transport is None
                or not transport.is_active()
            ):
                raise RuntimeError(
                    "SSH transport is not active"
                )

            #
            # -------------------------------------------------
            # Open raw SSH session
            # -------------------------------------------------
            #

            channel = (
                transport.open_session(
                    timeout=20
                )
            )

            channel.settimeout(
                10
            )

            channel.exec_command(
                command
            )

            stdout_chunks = []
            stderr_chunks = []

            total_stdout = 0
            total_stderr = 0

            start_time = time.monotonic()
            last_progress = start_time

            #
            # Hard upper limit.
            #
            timeout_seconds = 300

            #
            # -------------------------------------------------
            # STREAM stdout/stderr while command executes
            # -------------------------------------------------
            #

            while True:
                made_progress = False

                #
                # Drain stdout
                #
                while channel.recv_ready():
                    chunk = channel.recv(
                        65536
                    )

                    if not chunk:
                        break

                    stdout_chunks.append(
                        chunk
                    )

                    total_stdout += len(
                        chunk
                    )

                    made_progress = True

                #
                # Drain stderr
                #
                while (
                    channel.recv_stderr_ready()
                ):
                    chunk = (
                        channel.recv_stderr(
                            65536
                        )
                    )

                    if not chunk:
                        break

                    stderr_chunks.append(
                        chunk
                    )

                    total_stderr += len(
                        chunk
                    )

                    made_progress = True

                if made_progress:
                    last_progress = (
                        time.monotonic()
                    )

                #
                # Remote process has exited.
                #
                if channel.exit_status_ready():

                    #
                    # There may still be data buffered
                    # after exit status becomes ready.
                    #
                    while channel.recv_ready():
                        chunk = channel.recv(
                            65536
                        )

                        if not chunk:
                            break

                        stdout_chunks.append(
                            chunk
                        )

                        total_stdout += len(
                            chunk
                        )

                    while (
                        channel.recv_stderr_ready()
                    ):
                        chunk = (
                            channel.recv_stderr(
                                65536
                            )
                        )

                        if not chunk:
                            break

                        stderr_chunks.append(
                            chunk
                        )

                        total_stderr += len(
                            chunk
                        )

                    break

                elapsed = (
                    time.monotonic()
                    - start_time
                )

                if elapsed > timeout_seconds:
                    raise TimeoutError(
                        "Topology collection exceeded "
                        f"{timeout_seconds} seconds "
                        f"for sensor {self.sensor.name}. "
                        f"Received {total_stdout} stdout bytes "
                        f"and {total_stderr} stderr bytes."
                    )

                #
                # Periodic progress logging.
                #
                if (
                    time.monotonic()
                    - last_progress
                    >= 10
                ):
                    log.info(
                        "Topology collection still running "
                        "sensor=%s received=%d bytes",
                        self.sensor.name,
                        total_stdout,
                    )

                    last_progress = (
                        time.monotonic()
                    )

                time.sleep(
                    0.05
                )

            #
            # -------------------------------------------------
            # Exit status
            # -------------------------------------------------
            #

            exit_code = (
                channel.recv_exit_status()
            )

            raw_output = (
                b"".join(
                    stdout_chunks
                )
                .decode(
                    "utf-8",
                    errors="replace",
                )
                .strip()
            )

            raw_error = (
                b"".join(
                    stderr_chunks
                )
                .decode(
                    "utf-8",
                    errors="replace",
                )
                .strip()
            )

            log.info(
                "Topology helper completed "
                "sensor=%s exit_code=%d "
                "stdout_bytes=%d stderr_bytes=%d",
                self.sensor.name,
                exit_code,
                total_stdout,
                total_stderr,
            )

            if exit_code != 0:
                raise RuntimeError(
                    "Topology reader failed for "
                    f"{self.sensor.name}: "
                    f"{raw_error or raw_output or 'unknown error'}"
                )

            if not raw_output:
                raise RuntimeError(
                    "Topology reader returned "
                    f"no output from {self.sensor.name}"
                )

            #
            # -------------------------------------------------
            # JSON parsing
            # -------------------------------------------------
            #

            try:
                payload = json.loads(
                    raw_output
                )

            except json.JSONDecodeError as exc:
                preview = (
                    raw_output[:500]
                )

                raise RuntimeError(
                    "Invalid topology JSON from "
                    f"{self.sensor.name}: {exc}. "
                    f"Beginning of response: {preview}"
                ) from exc

            #
            # Force configured identity.
            #
            payload["sensor"] = (
                self.sensor.name
            )

            payload["tap"] = (
                self.sensor.tap
            )

            observations = (
                payload.get(
                    "observations",
                    [],
                )
            )

            edges = (
                payload.get(
                    "edges",
                    [],
                )
            )

            log.info(
                "Topology sensor %s returned "
                "%d observations and %d edges",
                self.sensor.name,
                len(observations),
                len(edges),
            )

            return payload

        finally:
            if channel is not None:
                try:
                    channel.close()
                except Exception:
                    pass

            client.close()


def normalize_edges(
    payload,
):
    """
    Convert topology JSON edges into TrafficEdge
    objects.
    """

    sensor = str(
        payload.get(
            "sensor",
            "",
        )
    )

    tap = str(
        payload.get(
            "tap",
            sensor,
        )
    )

    edges = []

    for item in payload.get(
        "edges",
        [],
    ):
        edges.append(
            TrafficEdge(
                sensor=sensor,

                tap=tap,

                source_ip=str(
                    item.get(
                        "source_ip",
                        "",
                    )
                ),

                destination_ip=str(
                    item.get(
                        "destination_ip",
                        "",
                    )
                ),

                source_port=(
                    item.get(
                        "source_port"
                    )
                ),

                destination_port=(
                    item.get(
                        "destination_port"
                    )
                ),

                protocol=str(
                    item.get(
                        "protocol",
                        "",
                    )
                ),

                service=str(
                    item.get(
                        "service",
                        "",
                    )
                ),

                connections=int(
                    item.get(
                        "connections",
                        0,
                    )
                    or 0
                ),

                bytes_total=int(
                    item.get(
                        "bytes_total",
                        0,
                    )
                    or 0
                ),

                first_seen=str(
                    item.get(
                        "first_seen",
                        "",
                    )
                ),

                last_seen=str(
                    item.get(
                        "last_seen",
                        "",
                    )
                ),
            )
        )

    return edges
