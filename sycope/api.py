import requests


class SycopeApi:
    def __init__(
        self,
        session: requests.Session,
        host: str,
        login: str,
        password: str,
        api_endpoint: str = "/npm/api/v1/",
    ):
        payload = {"username": login, "password": password}
        response = session.post(host + "/npm/api/v1/login", json=payload, verify=False)
        data = response.json()
        if data["status"] == 200:
            print("Login successful. Proceeding...")
            self.host = host
            self.session = session
            self.api_endpoint = api_endpoint
        else:
            # For debugging
            print("Could not log in to Sycope API")
            print(response.json())

    def log_out(self) -> requests.Response:
        repsonse = self.session.get(self.host + self.api_endpoint + "logout", verify=False)
        return repsonse

    def get_user_indicies(self) -> list:
        print("Searching in existing custom indexes...")
        r = self.session.get(
            self.host + self.api_endpoint + 'config-elements?filter=category="userIndex.index"', verify=False
        )
        all_data = r.json()["data"]
        if isinstance(all_data, list):
            return all_data
        else:
            return []

    def get_lookups(self) -> list:
        print("Searching in saved Lookups...")
        r = self.session.get(
            self.host
            + self.api_endpoint
            + 'config-elements?offset=0&limit=2147483647&filter=category = "lookup.lookup"',
            verify=False,
        )
        all_data = r.json()["data"]
        if isinstance(all_data, list):
            return all_data
        else:
            return []

    def get_lookup(self, lookup_name: str) -> tuple[str, dict]:
        all_data = self.get_lookups()
        lookup_id = [x["id"] for x in all_data if x["config"]["name"] == lookup_name]
        print("Searching in saved Lookups...")
        if lookup_id:
            r = self.session.get(
                self.host + self.api_endpoint + f"config-element-lookup/csvFile/{lookup_id}",
                verify=False,
            )

            saved_lookup = r.json()
            if isinstance(saved_lookup, dict):
                return str(lookup_id), saved_lookup
            else:
                return "0", {}
        else:
            print(f"Could not find lookup with the name {lookup_name}")
            return "0", {}

    def create_index(
        self,
        stream_name: str,
        fields: list,
        rotation: str,
        active: bool = True,
        store_raw: bool = True,
    ) -> None:
        payload = {
            "name": stream_name,
            "active": active,
            "rotation": rotation,
            "storeRaw": store_raw,
            "fields": fields,
        }
        response = self.session.post(
            self.host + self.api_endpoint + "config-element-index/user-index", json=payload, verify=False
        )
        data = response.json()
        if data["status"] == 200:
            print(f'New custom stream "{stream_name}" has been created.')
        else:
            # For debugging
            print("Could not create custom_index with API response:")
            print(response.json())
        return None

    def remove_index(
        self,
        indax_name_to_remove: str,
    ) -> None:
        all_data = self.get_user_indicies()
        id_to_remove = [x["id"] for x in all_data if x["config"]["name"] == indax_name_to_remove]
        if id_to_remove:
            index_id = id_to_remove[0]
            print(f'Found custom index "{indax_name_to_remove}" with ID "{index_id}".')
            r = self.session.delete(
                self.host + self.api_endpoint + "config-element-index/user-index/" + index_id,
                verify=False,
            )

            data = r.json()

            if data["status"] == 200:
                print(f'Custom index "{indax_name_to_remove}" has been successfully removed.')
            else:
                # For debugging
                print(f'Removing custom index "{indax_name_to_remove}" failed. Error message:')
                print(r.json())
        else:
            print(f"Could not find an index with the name {indax_name_to_remove}")
