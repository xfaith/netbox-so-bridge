import requests


class NetBoxClient:
    def __init__(self, url, token):
        self.base_url = url.rstrip("/") + "/api"
        self.session = requests.Session()
        self.session.headers.update({
            "Authorization": f"Bearer {token}",
            "Accept": "application/json",
        })

    def get_all(self, endpoint):
        url = f"{self.base_url}/{endpoint.lstrip('/')}"

        results = []

        while url:
            response = self.session.get(url, timeout=30)
            response.raise_for_status()

            data = response.json()
            results.extend(data["results"])
            url = data.get("next")

        return results

    def get_ip_addresses(self):
        return self.get_all("ipam/ip-addresses/")
