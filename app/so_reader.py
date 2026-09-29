import json
import logging
import os

import paramiko


log = logging.getLogger(
    "netbox-so-bridge.reader"
)


class SecurityOnionReader:

    def __init__(self):

        self.host = os.environ["SO_HOST"]

        self.port = int(
            os.getenv(
                "SO_PORT",
                "22"
            )
        )

        self.username = os.environ[
            "SO_USER"
        ]

        self.key_path = os.getenv(
            "SO_SSH_KEY",
            "/home/bridge/.ssh/id_ed25519"
        )

        self.helper = os.getenv(
            "SO_READER_HELPER",
            "/usr/local/sbin/netbox-so-observe"
        )

        self.hours = int(
            os.getenv(
                "SO_READER_HOURS",
                "24"
            )
        )

    def read(self):

        if not 1 <= self.hours <= 168:
            raise ValueError(
                "SO_READER_HOURS must be between 1 and 168"
            )

        key = (
            paramiko.Ed25519Key
            .from_private_key_file(
                self.key_path
            )
        )

        client = paramiko.SSHClient()

        client.set_missing_host_key_policy(
            paramiko.AutoAddPolicy()
        )

        log.info(
            "Connecting to Security Onion reader at %s",
            self.host
        )

        client.connect(
            hostname=self.host,
            port=self.port,
            username=self.username,
            pkey=key,
            timeout=15,
            banner_timeout=15,
            auth_timeout=15,
        )

        command = (
            f"sudo -n {self.helper} "
            f"--hours {self.hours}"
        )

        log.info(
            "Executing Security Onion command: %s",
            command
)

        try:

            stdin, stdout, stderr = (
                client.exec_command(
                    command,
                    timeout=120
                )
            )

            exit_code = (
                stdout.channel
                .recv_exit_status()
            )

            raw_output = (
                stdout.read()
                .decode("utf-8")
                .strip()
            )

            raw_error = (
                stderr.read()
                .decode("utf-8")
                .strip()
            )

            if exit_code != 0:
                raise RuntimeError(
                    "Security Onion reader failed: "
                    + (
                        raw_error
                        or raw_output
                        or "unknown error"
                    )
                )

            payload = json.loads(
                raw_output
            )

            assets = payload.get(
                "assets",
                {}
            )

            log.info(
                "Security Onion reader returned %d observed assets",
                len(assets)
            )

            return assets

        finally:
            client.close()
