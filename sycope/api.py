import requests


class SycopeApi:
    def __init__(
        self,
        session: requests.Session,
        host: str,
        login: str,
        password: str,
        api_endpoint: str = "/npm/api/v1/",
        api_endpoint_lookup: str = "config-element-lookup/csvFile",
        api_endpoint_lookup_subnet: str = "config-element-lookup/subnet",
    ):
        payload = {"username": login, "password": password}
        response = session.post(host + "/npm/api/v1/login", json=payload, verify=False)
        data = response.json()
        if data["status"] == 200:
            print("Login to Sycope API successful. Proceeding...")
            self.host = host
            self.session = session
            self.api_endpoint = api_endpoint
            self.api_endpoint_lookup = api_endpoint_lookup
            self.api_endpoint_lookup_subnet = api_endpoint_lookup_subnet
        else:
            # For debugging
            print("Could not log in to Sycope API")
            print(response.json())

    def log_out(self) -> requests.Response:
        response = self.session.get(self.host + self.api_endpoint + "logout", verify=False)
        data = response.json()
        if data["status"] == 200:
            print("Logged out from Sycope")
        else:
            # For debugging
            print("Logged out from Sycope was unsuccessful.")
            print(response.json())
        return response

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
        print("Getting all saved Lookups...")
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

    def get_lookup(self, lookup_name: str, lookup_type: str = "default") -> tuple[str, dict]:
        # Map lookup_type → URL suffix
        url_map = {
            "default": self.api_endpoint_lookup,
            "subnet": self.api_endpoint_lookup_subnet,
        }

        # pick the correct URL
        endpoint = url_map.get(lookup_type, self.api_endpoint_lookup)

        all_data = self.get_lookups()
        lookup_id = [x["id"] for x in all_data if x["config"]["name"] == lookup_name]
        print(f'Searching for the Lookup "{lookup_name}" in saved Lookups...')
        if lookup_id:
            lookup_id = lookup_id[0]

            # build URL dynamically based on type
            url = f"{self.host}{self.api_endpoint}{endpoint}/{lookup_id}"

            r = self.session.get(url, verify=False)

            saved_lookup = r.json()
            if isinstance(saved_lookup, dict):
                return str(lookup_id), saved_lookup
            else:
                return "0", {}
        else:
            print(f'Could not find lookup with the name "{lookup_name}".')
            return "0", {}

    def create_lookup(self, lookup_name: str, lookup):
        r = self.session.post(
            self.host + self.api_endpoint + self.api_endpoint_lookup, json=lookup, verify=False
        )
        data = r.json()
        if data["status"] == 200:
            lookup_id = data["id"]
            print(f'New Lookup "{lookup_name}" with ID "{lookup_id}" has been created.')
            return lookup_id
        else:
            # For debugging
            print("Something went wrong. Please analyze the output:")
            print(r.json())

    def edit_lookup(self, lookup_id: str, lookup, lookup_type: str = "default") -> None:
        url_map = {
            "default": self.api_endpoint_lookup,
            "subnet": self.api_endpoint_lookup_subnet,
        }
        # Select endpoint based on lookup_type
        endpoint = url_map.get(lookup_type, self.api_endpoint_lookup)
        # Build URL
        url = f"{self.host}{self.api_endpoint}{endpoint}/{lookup_id}"
        # Perform PUT request
        r = self.session.put(url, json=lookup, verify=False)
        data = r.json()

        if data["status"] == 200:
            print(f'Data in the Lookup ID "{lookup_id}" have been successfully modified.')
        else:
            # For debugging
            print("Something went wrong. Please analyze the output:")
            print(r.json())

    def privacy_check_lookup(self, lookup_id: str):
        print("Checking privacy configuration...")
        r = self.session.get(
            self.host + self.api_endpoint + "permissions/CONFIGURATION.lookup.lookup/" + lookup_id,
            verify=False,
        )
        data = r.json()
        if data and data["objectId"] == lookup_id:
            savedsidPerms = data["sidPerms"]

            # Definition for Public Privacy
            sidPermsPublic = [{"sid": "ROLE_USER", "perms": ["VIEW"]}]
            # Definition for Private Privacy
            sidPermsPrivate = []

            # Checking defined Privacy in Sycope
            savedsidPermsValue = ""
            if savedsidPerms == sidPermsPublic:
                savedsidPermsValue = "Public"
            elif savedsidPerms == sidPermsPrivate:
                savedsidPermsValue = "Private"
            else:
                print(
                    f'Script could not identify the Privacy configuration in the Lookup ID "{lookup_id}". Are you using custom Shared Privacy?'
                )
            return savedsidPermsValue
        else:
            # For debugging
            print("Something went wrong. Please analyze the output:")
            print(r.json())

    def privacy_edit_lookup(self, lookup_id: str, lookup_privacy) -> None:
        savedsidPermsValue = ""
        sidPerms_saved = ""
        savedsidPermsValue = self.privacy_check_lookup(lookup_id)
        sidPerms_Public = [{"sid": "ROLE_USER", "perms": ["VIEW"]}]
        sidPerms_Private = []
        data = None
        response = None

        if savedsidPermsValue == lookup_privacy:
            print(f'Privacy in the Lookup ID "{lookup_id}" is identical to the input. No changes required.')
        elif lookup_privacy == "Public":
            response = self.session.put(
                self.host + self.api_endpoint + "permissions/CONFIGURATION.lookup.lookup/" + lookup_id,
                json=sidPerms_Public,
                verify=False,
            )
            sidPerms_saved = sidPerms_Public
        elif lookup_privacy == "Private":
            response = self.session.put(
                self.host + self.api_endpoint + "permissions/CONFIGURATION.lookup.lookup/" + lookup_id,
                json=sidPerms_Private,
                verify=False,
            )
            sidPerms_saved = sidPerms_Private
        else:
            print("Please choose supported privacy options - Public or Private.")

        if response:
            data = response.json()
            if data["sidPerms"] == sidPerms_saved:
                print(
                    f'Privacy for the Lookup ID "{lookup_id}" have been successfully modified to "{lookup_privacy}".'
                )
            else:
                # For debugging
                print("Could not create custom_index with API response:")
                print(response.json())
        else:
            return None

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
