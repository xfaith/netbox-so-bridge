import logging
import os
import time

from mappings import generate_mapping_file
from netbox import NetBoxClient
from security_onion import SecurityOnionPublisher
from so_reader import SecurityOnionReader


logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO").upper(),
    format="%(asctime)s %(levelname)s %(message)s",
)

log = logging.getLogger("netbox-so-bridge")


def env_bool(name, default=False):
    value = os.getenv(
        name,
        "true" if default else "false",
    )

    return value.strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }


def run_sync():
    #
    # -------------------------------------------------
    # Runtime configuration
    # -------------------------------------------------
    #

    netbox_url = os.environ["NETBOX_URL"]
    netbox_token = os.environ["NETBOX_TOKEN"]

    output_file = os.getenv(
        "OUTPUT_FILE",
        "/data/ip-descriptions.csv",
    )

    dry_run = env_bool(
        "DRY_RUN",
        default=True,
    )

    reader_enabled = env_bool(
        "SO_READER_ENABLED",
        default=False,
    )

    topology_enabled = env_bool(
        "TOPOLOGY_ENABLED",
        default=False,
    )

    #
    # -------------------------------------------------
    # NetBox inventory
    # -------------------------------------------------
    #

    log.info(
        "Querying NetBox"
    )

    netbox_client = NetBoxClient(
        netbox_url,
        netbox_token,
    )

    addresses = (
        netbox_client.get_ip_addresses()
    )

    log.info(
        "Retrieved %d IP addresses from NetBox",
        len(addresses),
    )

    #
    # -------------------------------------------------
    # Existing Security Onion passive identity reader
    # -------------------------------------------------
    #

    observations = {}

    if reader_enabled:
        try:
            log.info(
                "Querying Security Onion passive observations"
            )

            so_reader = (
                SecurityOnionReader()
            )

            observations = (
                so_reader.read()
            )

            log.info(
                "Retrieved %d observed assets from Security Onion",
                len(observations),
            )

        except Exception:
            log.exception(
                "Security Onion reader failed; "
                "continuing with NetBox data only"
            )

            observations = {}

    else:
        log.info(
            "Security Onion reader disabled"
        )

    #
    # -------------------------------------------------
    # Security Onion IP-description mapping
    # -------------------------------------------------
    #

    count = generate_mapping_file(
        addresses,
        output_file,
        observations,
    )

    log.info(
        "Generated %d Security Onion mappings",
        count,
    )

    if count == 0:
        raise RuntimeError(
            "Generated mapping file contains zero entries; "
            "refusing to publish"
        )

    #
    # -------------------------------------------------
    # Phase 3:
    # Traffic topology + sensor/TAP coverage
    # -------------------------------------------------
    #

    if topology_enabled:
        try:
            from topology_phase import (
                run_topology_phase,
            )

            log.info(
                "Running topology and sensor coverage phase"
            )

            summary = (
                run_topology_phase(
                    addresses
                )
            )

            log.info(
                "Topology phase complete: %s",
                summary,
            )

        except Exception:
            #
            # The topology module is intentionally isolated.
            # A topology problem should not stop the existing
            # NetBox -> Security Onion mapping workflow.
            #
            log.exception(
                "Topology phase failed; "
                "continuing with normal mapping workflow"
            )

    else:
        log.info(
            "Topology phase disabled"
        )

    #
    # -------------------------------------------------
    # Publish IP mappings to Security Onion
    # -------------------------------------------------
    #

    if dry_run:
        log.info(
            "DRY_RUN enabled; "
            "not publishing to Security Onion"
        )

        return

    log.info(
        "Publishing mappings to Security Onion"
    )

    publisher = (
        SecurityOnionPublisher()
    )

    result = publisher.publish(
        output_file
    )

    if result:
        log.info(
            "Security Onion publish successful: %s",
            result,
        )

    else:
        log.info(
            "Security Onion publish successful"
        )


def main():
    #
    # -------------------------------------------------
    # Synchronization interval
    # -------------------------------------------------
    #

    interval = int(
        os.getenv(
            "SYNC_INTERVAL",
            "900",
        )
    )

    if interval < 60:
        log.warning(
            "SYNC_INTERVAL=%d is too low; "
            "forcing minimum interval of 60 seconds",
            interval,
        )

        interval = 60

    log.info(
        "NetBox-Security Onion bridge starting"
    )

    log.info(
        "Synchronization interval: %d seconds",
        interval,
    )

    #
    # -------------------------------------------------
    # Main synchronization loop
    # -------------------------------------------------
    #

    while True:
        try:
            run_sync()

        except KeyboardInterrupt:
            log.info(
                "Shutdown requested"
            )

            break

        except Exception:
            log.exception(
                "Synchronization failed"
            )

        log.info(
            "Next synchronization in %d seconds",
            interval,
        )

        try:
            time.sleep(
                interval
            )

        except KeyboardInterrupt:
            log.info(
                "Shutdown requested"
            )

            break


if __name__ == "__main__":
    main()
