#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
phpIPAM API Wrapper

This module provides a Python wrapper for the phpIPAM REST API.
It handles authentication, token management, and provides convenient methods
for retrieving IP address management data from phpIPAM.

Features:
- Token-based authentication with automatic renewal
- Comprehensive methods for sections, subnets, addresses, devices, VLANs
- Error handling and logging
- Support for custom fields and search operations
"""

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import requests

logger = logging.getLogger(__name__)


class PhpipamApi:
    """
    phpIPAM API wrapper class for data synchronization.

    Provides methods to interact with phpIPAM REST API endpoints.
    """

    def __init__(
        self,
        session: requests.Session,
        host: str,
        app_id: str,
        username: str,
        password: str,
        api_base: str = "/api",
    ):
        """
        Initialize phpIPAM API connection.

        Args:
            session: requests.Session object
            host: phpIPAM host URL (e.g., 'https://ipam.example.com')
            app_id: API application ID configured in phpIPAM
            username: phpIPAM username
            password: phpIPAM password
            api_base: API base path (default: '/api')
        """
        self.session = session
        self.host = host.rstrip("/")
        self.app_id = app_id
        self.username = username
        self.password = password
        self.api_base = api_base.rstrip("/")
        self.token = None
        self.token_expires = None

        logger.debug(f"Initializing PhpipamApi:")
        logger.debug(f"  Host: {self.host}")
        logger.debug(f"  App ID: {self.app_id}")
        logger.debug(f"  Username: {self.username}")
        logger.debug(f"  API base: {self.api_base}")

        # Authenticate and get token
        self._authenticate()

    def _authenticate(self) -> None:
        """
        Authenticate to phpIPAM API and obtain access token.

        Raises:
            Exception: If authentication fails
        """
        url = f"{self.host}{self.api_base}/{self.app_id}/user/"
        auth = (self.username, self.password)

        logger.debug(f"Authenticating to phpIPAM...")
        logger.debug(f"  URL: {url}")
        logger.debug(f"  User: {self.username}")
        logging.info(f"Using URL: {url}")

        try:
            response = self.session.post(url, auth=auth, verify=False)
            logger.debug(f"Response status code: {response.status_code}")
            logger.debug(f"Response headers: {dict(response.headers)}")

            data = response.json()
            logger.debug(f"Response data keys: {list(data.keys())}")

            if response.status_code == 200 and data.get("success"):
                self.token = data["data"]["token"]
                logger.debug(f"Token received (first 20 chars): {self.token[:20] if len(self.token) > 20 else '***'}...")
                logging.info(f"phpIPAM response: {data}")
                self.token_expires = data["data"]["expires"]
                logger.debug(f"Token expires: {self.token_expires}")
                self.session.headers.update({"phpipam-token": self.token})
                logging.info("Login to phpIPAM API successful. Proceeding...")
            else:
                error_msg = data.get("message", "Unknown error")
                logger.debug(f"Authentication failed: {error_msg}")
                logger.debug(f"Full response: {data}")
                raise Exception(f"phpIPAM authentication failed: {error_msg}")

        except requests.exceptions.RequestException as e:
            logger.debug(f"Connection error: {e}")
            raise Exception(f"Failed to connect to phpIPAM API: {e}")

    def _check_token(self) -> None:
        """Check if token is expired and renew if necessary."""
        logger.debug(f"Checking token expiration: {self.token_expires}")

        if self.token_expires:
            try:
                # Parse and normalize token expiration timestamp
                expires_dt = datetime.fromisoformat(self.token_expires.replace("Z", "+00:00")).astimezone(
                    timezone.utc
                )
                now = datetime.now(timezone.utc)

                logger.debug(f"Token expires at: {expires_dt}")
                logger.debug(f"Current time: {now}")

                # Compare with current UTC time
                if now >= expires_dt:
                    logging.info("Token expired, re-authenticating...")
                    logger.debug("Token is expired, re-authenticating...")
                    self._authenticate()
                else:
                    time_remaining = expires_dt - now
                    logger.debug(f"Token still valid for: {time_remaining}")
            except Exception as e:
                logger.debug(f"Error checking token expiration: {e}")
                logging.error(f"Error checking token expiration: {e}")
                self._authenticate()

    def _make_request(
        self, method: str, endpoint: str, params: Optional[Dict] = None, json_data: Optional[Dict] = None
    ) -> Dict[str, Any]:
        """
        Make API request with automatic token refresh.

        Args:
            method: HTTP method (GET, POST, PATCH, DELETE)
            endpoint: API endpoint path
            params: Query parameters
            json_data: JSON body data

        Returns:
            API response data

        Raises:
            Exception: If request fails
        """
        self._check_token()
        url = f"{self.host}{self.api_base}/{self.app_id}/{endpoint}"

        logger.debug(f"--- API Request ---")
        logger.debug(f"Method: {method}")
        logger.debug(f"URL: {url}")
        if params:
            logger.debug(f"Params: {params}")
        if json_data:
            logger.debug(f"JSON data: {json_data}")

        logging.info(f"Using URL: {url}")

        try:
            response = self.session.request(
                method=method, url=url, params=params, json=json_data, verify=False
            )

            logger.debug(f"Response status code: {response.status_code}")
            logger.debug(f"Response headers: {dict(response.headers)}")

            data = response.json()
            logger.debug(f"Response data keys: {list(data.keys())}")

            if data.get("success"):
                result = data.get("data", {})
                if isinstance(result, list):
                    logger.debug(f"Response: list with {len(result)} items")
                elif isinstance(result, dict):
                    logger.debug(f"Response: dict with keys {list(result.keys())}")
                else:
                    logger.debug(f"Response: {type(result).__name__}")
                return result
            else:
                error_msg = data.get("message", "Unknown error")
                logger.debug(f"API request failed: {error_msg}")
                logger.debug(f"Full error response: {data}")
                logging.error(f"API request failed: {error_msg}")
                return {}

        except requests.exceptions.RequestException as e:
            logger.debug(f"Request exception: {e}")
            logging.error(f"Request error: {e}")
            return {}

    def logout(self) -> None:
        """Logout and invalidate the current token."""
        logger.debug("Logging out from phpIPAM...")

        if self.token:
            try:
                url = f"{self.host}{self.api_base}/{self.app_id}/user/"
                logger.debug(f"Logout URL: {url}")

                response = self.session.delete(url, verify=False)
                logger.debug(f"Logout response status: {response.status_code}")

                if response.status_code == 200:
                    logging.info("Logged out from phpIPAM API")
                    logger.debug("Logout successful")
                else:
                    logger.debug(f"Logout returned status {response.status_code}")

                self.token = None
                self.token_expires = None
            except Exception as e:
                logger.debug(f"Logout error: {e}")
                logging.warning(f"Logout failed: {e}")
        else:
            logger.debug("No token to invalidate")

    # ========== SECTIONS ==========

    def get_all_sections(self) -> List[Dict[str, Any]]:
        """
        Get all sections.

        Returns:
            List of section dictionaries
        """
        logger.debug("get_all_sections called")
        logging.info("Fetching all sections...")
        result = self._make_request("GET", "sections/")
        logger.debug(f"Sections retrieved: {len(result) if isinstance(result, list) else 'not a list'}")
        return result if isinstance(result, list) else []

    def get_section(self, section_id: int) -> Dict[str, Any]:
        """
        Get section by ID.

        Args:
            section_id: Section ID

        Returns:
            Section dictionary
        """
        logger.debug(f"get_section called: section_id={section_id}")
        logging.info(f"Fetching section ID {section_id}...")
        return self._make_request("GET", f"sections/{section_id}/")

    def get_section_subnets(self, section_id: int) -> List[Dict[str, Any]]:
        """
        Get all subnets in a section.

        Args:
            section_id: Section ID

        Returns:
            List of subnet dictionaries
        """
        logger.debug(f"get_section_subnets called: section_id={section_id}")
        logging.info(f"Fetching subnets for section ID {section_id}...")
        result = self._make_request("GET", f"sections/{section_id}/subnets/")
        logger.debug(f"Subnets in section {section_id}: {len(result) if isinstance(result, list) else 'not a list'}")
        return result if isinstance(result, list) else []

    # ========== SUBNETS ==========

    def get_all_subnets(self) -> List[Dict[str, Any]]:
        """
        Get all subnets.

        Returns:
            List of subnet dictionaries
        """
        logger.debug("get_all_subnets called")
        logging.info("Fetching all subnets...")
        result = self._make_request("GET", "subnets/")
        logger.debug(f"Total subnets retrieved: {len(result) if isinstance(result, list) else 'not a list'}")
        return result if isinstance(result, list) else []

    def get_subnet(self, subnet_id: int) -> Dict[str, Any]:
        """
        Get subnet by ID.

        Args:
            subnet_id: Subnet ID

        Returns:
            Subnet dictionary
        """
        logger.debug(f"get_subnet called: subnet_id={subnet_id}")
        logging.info(f"Fetching subnet ID {subnet_id}...")
        return self._make_request("GET", f"subnets/{subnet_id}/")

    def search_subnet(self, cidr: str) -> Dict[str, Any]:
        """
        Search for subnet by CIDR notation.

        Args:
            cidr: CIDR notation (e.g., '192.168.1.0/24')

        Returns:
            Subnet dictionary
        """
        logger.debug(f"search_subnet called: cidr={cidr}")
        logging.info(f"Searching for subnet {cidr}...")
        return self._make_request("GET", f"subnets/cidr/{cidr}/")

    def get_subnet_addresses(self, subnet_id: int) -> List[Dict[str, Any]]:
        """
        Get all addresses in a subnet.

        Args:
            subnet_id: Subnet ID

        Returns:
            List of address dictionaries
        """
        logger.debug(f"get_subnet_addresses called: subnet_id={subnet_id}")
        logging.info(f"Fetching addresses for subnet ID {subnet_id}...")
        result = self._make_request("GET", f"subnets/{subnet_id}/addresses/")
        logger.debug(f"Addresses in subnet {subnet_id}: {len(result) if isinstance(result, list) else 'not a list'}")
        return result if isinstance(result, list) else []

    def get_subnet_usage(self, subnet_id: int) -> Dict[str, Any]:
        """
        Get subnet usage statistics.

        Args:
            subnet_id: Subnet ID

        Returns:
            Dictionary with usage statistics
        """
        logger.debug(f"get_subnet_usage called: subnet_id={subnet_id}")
        logging.info(f"Fetching usage for subnet ID {subnet_id}...")
        return self._make_request("GET", f"subnets/{subnet_id}/usage/")

    def get_subnet_first_free(self, subnet_id: int) -> Optional[str]:
        """
        Get first available IP address in subnet.

        Args:
            subnet_id: Subnet ID

        Returns:
            First free IP address or None
        """
        logger.debug(f"get_subnet_first_free called: subnet_id={subnet_id}")
        logging.info(f"Fetching first free IP for subnet ID {subnet_id}...")
        result = self._make_request("GET", f"subnets/{subnet_id}/first_free/")
        logger.debug(f"First free IP in subnet {subnet_id}: {result}")
        return result if isinstance(result, str) else None

    # ========== ADDRESSES ==========

    def get_address(self, address_id: int) -> Dict[str, Any]:
        """
        Get address by ID.

        Args:
            address_id: Address ID

        Returns:
            Address dictionary
        """
        logger.debug(f"get_address called: address_id={address_id}")
        logging.info(f"Fetching address ID {address_id}...")
        return self._make_request("GET", f"addresses/{address_id}/")

    def search_address(self, ip_address: str) -> Dict[str, Any]:
        """
        Search for address by IP.

        Args:
            ip_address: IP address to search

        Returns:
            Address dictionary
        """
        logger.debug(f"search_address called: ip_address={ip_address}")
        logging.info(f"Searching for address {ip_address}...")
        return self._make_request("GET", f"addresses/search/{ip_address}/")

    def search_hostname(self, hostname: str) -> List[Dict[str, Any]]:
        """
        Search for addresses by hostname.

        Args:
            hostname: Hostname to search

        Returns:
            List of address dictionaries
        """
        logger.debug(f"search_hostname called: hostname={hostname}")
        logging.info(f"Searching for hostname {hostname}...")
        result = self._make_request("GET", f"addresses/search_hostname/{hostname}/")
        logger.debug(f"Addresses found for hostname {hostname}: {len(result) if isinstance(result, list) else 'not a list'}")
        return result if isinstance(result, list) else []

    def search_mac(self, mac_address: str) -> List[Dict[str, Any]]:
        """
        Search for addresses by MAC address.

        Args:
            mac_address: MAC address to search

        Returns:
            List of address dictionaries
        """
        logger.debug(f"search_mac called: mac_address={mac_address}")
        logging.info(f"Searching for MAC address {mac_address}...")
        result = self._make_request("GET", f"addresses/search_mac/{mac_address}/")
        logger.debug(f"Addresses found for MAC {mac_address}: {len(result) if isinstance(result, list) else 'not a list'}")
        return result if isinstance(result, list) else []

    def get_addresses_by_tag(self, tag_id: int) -> List[Dict[str, Any]]:
        """
        Get all addresses with specific tag.

        Args:
            tag_id: Tag ID

        Returns:
            List of address dictionaries
        """
        logger.debug(f"get_addresses_by_tag called: tag_id={tag_id}")
        logging.info(f"Fetching addresses for tag ID {tag_id}...")
        result = self._make_request("GET", f"addresses/tags/{tag_id}/")
        logger.debug(f"Addresses with tag {tag_id}: {len(result) if isinstance(result, list) else 'not a list'}")
        return result if isinstance(result, list) else []

    # ========== DEVICES ==========

    def get_all_devices(self) -> List[Dict[str, Any]]:
        """
        Get all devices.

        Returns:
            List of device dictionaries
        """
        logger.debug("get_all_devices called")
        logging.info("Fetching all devices...")
        result = self._make_request("GET", "devices/")
        logger.debug(f"Total devices retrieved: {len(result) if isinstance(result, list) else 'not a list'}")
        return result if isinstance(result, list) else []

    def get_device(self, device_id: int) -> Dict[str, Any]:
        """
        Get device by ID.

        Args:
            device_id: Device ID

        Returns:
            Device dictionary
        """
        logger.debug(f"get_device called: device_id={device_id}")
        logging.info(f"Fetching device ID {device_id}...")
        return self._make_request("GET", f"devices/{device_id}/")

    def get_device_addresses(self, device_id: int) -> List[Dict[str, Any]]:
        """
        Get all addresses associated with a device.

        Args:
            device_id: Device ID

        Returns:
            List of address dictionaries
        """
        logger.debug(f"get_device_addresses called: device_id={device_id}")
        logging.info(f"Fetching addresses for device ID {device_id}...")
        result = self._make_request("GET", f"devices/{device_id}/addresses/")
        logger.debug(f"Addresses for device {device_id}: {len(result) if isinstance(result, list) else 'not a list'}")
        return result if isinstance(result, list) else []

    def get_device_subnets(self, device_id: int) -> List[Dict[str, Any]]:
        """
        Get all subnets associated with a device.

        Args:
            device_id: Device ID

        Returns:
            List of subnet dictionaries
        """
        logger.debug(f"get_device_subnets called: device_id={device_id}")
        logging.info(f"Fetching subnets for device ID {device_id}...")
        result = self._make_request("GET", f"devices/{device_id}/subnets/")
        logger.debug(f"Subnets for device {device_id}: {len(result) if isinstance(result, list) else 'not a list'}")
        return result if isinstance(result, list) else []

    # ========== VLANS ==========

    def get_all_vlans(self) -> List[Dict[str, Any]]:
        """
        Get all VLANs.

        Returns:
            List of VLAN dictionaries
        """
        logger.debug("get_all_vlans called")
        logging.info("Fetching all VLANs...")
        result = self._make_request("GET", "vlan/")
        logger.debug(f"Total VLANs retrieved: {len(result) if isinstance(result, list) else 'not a list'}")
        return result if isinstance(result, list) else []

    def get_vlan(self, vlan_id: int) -> Dict[str, Any]:
        """
        Get VLAN by ID.

        Args:
            vlan_id: VLAN ID

        Returns:
            VLAN dictionary
        """
        logger.debug(f"get_vlan called: vlan_id={vlan_id}")
        logging.info(f"Fetching VLAN ID {vlan_id}...")
        return self._make_request("GET", f"vlan/{vlan_id}/")

    def get_vlan_subnets(self, vlan_id: int) -> List[Dict[str, Any]]:
        """
        Get all subnets in a VLAN.

        Args:
            vlan_id: VLAN ID

        Returns:
            List of subnet dictionaries
        """
        logger.debug(f"get_vlan_subnets called: vlan_id={vlan_id}")
        logging.info(f"Fetching subnets for VLAN ID {vlan_id}...")
        result = self._make_request("GET", f"vlan/{vlan_id}/subnets/")
        logger.debug(f"Subnets in VLAN {vlan_id}: {len(result) if isinstance(result, list) else 'not a list'}")
        return result if isinstance(result, list) else []

    # ========== VRFs ==========

    def get_all_vrfs(self) -> List[Dict[str, Any]]:
        """
        Get all VRFs.

        Returns:
            List of VRF dictionaries
        """
        logger.debug("get_all_vrfs called")
        logging.info("Fetching all VRFs...")
        result = self._make_request("GET", "vrf/")
        logger.debug(f"Total VRFs retrieved: {len(result) if isinstance(result, list) else 'not a list'}")
        return result if isinstance(result, list) else []

    def get_vrf(self, vrf_id: int) -> Dict[str, Any]:
        """
        Get VRF by ID.

        Args:
            vrf_id: VRF ID

        Returns:
            VRF dictionary
        """
        logger.debug(f"get_vrf called: vrf_id={vrf_id}")
        logging.info(f"Fetching VRF ID {vrf_id}...")
        return self._make_request("GET", f"vrf/{vrf_id}/")

    def get_vrf_subnets(self, vrf_id: int) -> List[Dict[str, Any]]:
        """
        Get all subnets in a VRF.

        Args:
            vrf_id: VRF ID

        Returns:
            List of subnet dictionaries
        """
        logger.debug(f"get_vrf_subnets called: vrf_id={vrf_id}")
        logging.info(f"Fetching subnets for VRF ID {vrf_id}...")
        result = self._make_request("GET", f"vrf/{vrf_id}/subnets/")
        logger.debug(f"Subnets in VRF {vrf_id}: {len(result) if isinstance(result, list) else 'not a list'}")
        return result if isinstance(result, list) else []

    # ========== L2 DOMAINS ==========

    def get_all_l2domains(self) -> List[Dict[str, Any]]:
        """
        Get all L2 domains.

        Returns:
            List of L2 domain dictionaries
        """
        logger.debug("get_all_l2domains called")
        logging.info("Fetching all L2 domains...")
        result = self._make_request("GET", "l2domains/")
        logger.debug(f"Total L2 domains retrieved: {len(result) if isinstance(result, list) else 'not a list'}")
        return result if isinstance(result, list) else []

    def get_l2domain(self, domain_id: int) -> Dict[str, Any]:
        """
        Get L2 domain by ID.

        Args:
            domain_id: L2 domain ID

        Returns:
            L2 domain dictionary
        """
        logger.debug(f"get_l2domain called: domain_id={domain_id}")
        logging.info(f"Fetching L2 domain ID {domain_id}...")
        return self._make_request("GET", f"l2domains/{domain_id}/")

    def get_l2domain_vlans(self, domain_id: int) -> List[Dict[str, Any]]:
        """
        Get all VLANs in an L2 domain.

        Args:
            domain_id: L2 domain ID

        Returns:
            List of VLAN dictionaries
        """
        logger.debug(f"get_l2domain_vlans called: domain_id={domain_id}")
        logging.info(f"Fetching VLANs for L2 domain ID {domain_id}...")
        result = self._make_request("GET", f"l2domains/{domain_id}/vlans/")
        logger.debug(f"VLANs in L2 domain {domain_id}: {len(result) if isinstance(result, list) else 'not a list'}")
        return result if isinstance(result, list) else []

    # ========== TAGS ==========

    def get_all_tags(self) -> List[Dict[str, Any]]:
        """
        Get all address tags.

        Returns:
            List of tag dictionaries
        """
        logger.debug("get_all_tags called")
        logging.info("Fetching all tags...")
        result = self._make_request("GET", "tools/tags/")
        logger.debug(f"Total tags retrieved: {len(result) if isinstance(result, list) else 'not a list'}")
        return result if isinstance(result, list) else []

    # ========== HELPER METHODS ==========

    def get_all_addresses_all_subnets(self) -> List[Dict[str, Any]]:
        """
        Get all addresses from all subnets.

        This is a convenience method that iterates through all subnets
        and retrieves all addresses.

        Returns:
            List of all address dictionaries with subnet information
        """
        logger.debug("get_all_addresses_all_subnets called")
        logging.info("Fetching all addresses from all subnets...")

        all_addresses = []
        subnets = self.get_all_subnets()
        logger.debug(f"Processing {len(subnets)} subnets")

        for i, subnet in enumerate(subnets, 1):
            subnet_id = subnet.get("id")
            if subnet_id:
                logger.debug(f"Processing subnet {i}/{len(subnets)}: id={subnet_id}, cidr={subnet.get('subnet')}/{subnet.get('mask')}")
                addresses = self.get_subnet_addresses(subnet_id)

                # Add subnet information to each address
                for addr in addresses:
                    addr["subnet_info"] = {
                        "subnet": subnet.get("subnet"),
                        "mask": subnet.get("mask"),
                        "description": subnet.get("description"),
                        "section": subnet.get("sectionId"),
                        "vlan": subnet.get("vlanId"),
                        "vrf": subnet.get("vrfId"),
                    }
                    all_addresses.append(addr)

                logger.debug(f"  Subnet {subnet_id}: {len(addresses)} addresses")

            # Log progress every 10 subnets
            if i % 10 == 0:
                logger.debug(f"Progress: {i}/{len(subnets)} subnets processed, {len(all_addresses)} total addresses")

        logger.debug(f"Total addresses retrieved: {len(all_addresses)}")
        logging.info(f"Retrieved {len(all_addresses)} total addresses")
        return all_addresses
