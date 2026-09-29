import os
import paramiko


class SecurityOnionPublisher:
    def __init__(self):
        self.host = os.environ["SO_HOST"]
        self.port = int(os.getenv("SO_PORT", "22"))
        self.username = os.environ["SO_USER"]
        self.key_path = os.getenv("SO_SSH_KEY", "/ssh/id_ed25519")

        self.remote_temp = os.getenv(
            "SO_REMOTE_TEMP",
            "/home/netbox-sync/ip-descriptions.csv.tmp"
        )

        self.helper = os.getenv(
            "SO_HELPER",
            "/usr/local/sbin/update-so-ip-mappings.sh"
        )

    def publish(self, local_file):
        key = paramiko.Ed25519Key.from_private_key_file(self.key_path)

        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        client.connect(
            hostname=self.host,
            port=self.port,
            username=self.username,
            pkey=key,
            timeout=15,
        )

        try:
            sftp = client.open_sftp()
            try:
                sftp.put(local_file, self.remote_temp)
            finally:
                sftp.close()

            command = f"sudo {self.helper} {self.remote_temp}"

            stdin, stdout, stderr = client.exec_command(command)

            exit_code = stdout.channel.recv_exit_status()

            output = stdout.read().decode().strip()
            error = stderr.read().decode().strip()

            if exit_code != 0:
                raise RuntimeError(
                    f"Security Onion publish failed: {error or output}"
                )

            return output

        finally:
            client.close()
