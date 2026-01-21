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
        logging.info(f"Using URL: {url}")

        try:
            response = self.session.post(url, auth=auth, verify=False)
            data = response.json()

            if response.status_code == 200 and data.get("success"):

                self.token = data["data"]["token"]
                logging.info(f"phpIPAM response: {data}")
                self.token_expires = data["data"]["expires"]
                self.session.headers.update({"phpipam-token": self.token})
                logging.info("Login to phpIPAM API successful. Proceeding...")
            else:
                error_msg = data.get("message", "Unknown error")
                raise Exception(f"phpIPAM authentication failed: {error_msg}")

        except requests.exceptions.RequestException as e:
            raise Exception(f"Failed to connect to phpIPAM API: {e}")

    def _check_token(self) -> None:
        """Check if token is expired and renew if necessary."""
        if self.token_expires:
            try:
                # Parse and normalize token expiration timestamp
                expires_dt = datetime.fromisoformat(self.token_expires.replace("Z", "+00:00")).astimezone(
                    timezone.utc
                )

                # Compare with current UTC time
                if datetime.now(timezone.utc) >= expires_dt:
                    logging.info("Token expired, re-authenticating...")
                    self._authenticate()
            except Exception as e:
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
        logging.info(f"Using URL: {url}")

        try:
            response = self.session.request(
                method=method, url=url, params=params, json=json_data, verify=False
            )
            data = response.json()

            if data.get("success"):
                return data.get("data", {})
            else:
                error_msg = data.get("message", "Unknown error")
                logging.error(f"API request failed: {error_msg}")
                return {}

        except requests.exceptions.RequestException as e:
            logging.error(f"Request error: {e}")
            return {}

    def logout(self) -> None:
        """Logout and invalidate the current token."""
        if self.token:
            try:
                url = f"{self.host}{self.api_base}/{self.app_id}/user/"
                response = self.session.delete(url, verify=False)
                if response.status_code == 200:
                    logging.info("Logged out from phpIPAM API")
                self.token = None
                self.token_expires = None
            except Exception as e:
                logging.warning(f"Logout failed: {e}")

    # ========== SECTIONS ==========

    def get_all_sections(self) -> List[Dict[str, Any]]:
        """
        Get all sections.

        Returns:
            List of section dictionaries
        """
        logging.info("Fetching all sections...")
        result = self._make_request("GET", "sections/")
        return result if isinstance(result, list) else []

    def get_section(self, section_id: int) -> Dict[str, Any]:
        """
        Get section by ID.

        Args:
            section_id: Section ID

        Returns:
            Section dictionary
        """
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
        logging.info(f"Fetching subnets for section ID {section_id}...")
        result = self._make_request("GET", f"sections/{section_id}/subnets/")
        return result if isinstance(result, list) else []

    # ========== SUBNETS ==========

    def get_all_subnets(self) -> List[Dict[str, Any]]:
        """
        Get all subnets.

        Returns:
            List of subnet dictionaries
        """
        logging.info("Fetching all subnets...")
        result = self._make_request("GET", "subnets/")

        return result if isinstance(result, list) else []

    def get_subnet(self, subnet_id: int) -> Dict[str, Any]:
        """
        Get subnet by ID.

        Args:
            subnet_id: Subnet ID

        Returns:
            Subnet dictionary
        """
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
        logging.info(f"Fetching addresses for subnet ID {subnet_id}...")
        result = self._make_request("GET", f"subnets/{subnet_id}/addresses/")
        return result if isinstance(result, list) else []

    def get_subnet_usage(self, subnet_id: int) -> Dict[str, Any]:
        """
        Get subnet usage statistics.

        Args:
            subnet_id: Subnet ID

        Returns:
            Dictionary with usage statistics
        """
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
        logging.info(f"Fetching first free IP for subnet ID {subnet_id}...")
        result = self._make_request("GET", f"subnets/{subnet_id}/first_free/")
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
        logging.info(f"Searching for hostname {hostname}...")
        result = self._make_request("GET", f"addresses/search_hostname/{hostname}/")
        return result if isinstance(result, list) else []

    def search_mac(self, mac_address: str) -> List[Dict[str, Any]]:
        """
        Search for addresses by MAC address.

        Args:
            mac_address: MAC address to search

        Returns:
            List of address dictionaries
        """
        logging.info(f"Searching for MAC address {mac_address}...")
        result = self._make_request("GET", f"addresses/search_mac/{mac_address}/")
        return result if isinstance(result, list) else []

    def get_addresses_by_tag(self, tag_id: int) -> List[Dict[str, Any]]:
        """
        Get all addresses with specific tag.

        Args:
            tag_id: Tag ID

        Returns:
            List of address dictionaries
        """
        logging.info(f"Fetching addresses for tag ID {tag_id}...")
        result = self._make_request("GET", f"addresses/tags/{tag_id}/")
        return result if isinstance(result, list) else []

    # ========== DEVICES ==========

    def get_all_devices(self) -> List[Dict[str, Any]]:
        """
        Get all devices.

        Returns:
            List of device dictionaries
        """
        logging.info("Fetching all devices...")
        result = self._make_request("GET", "devices/")
        return result if isinstance(result, list) else []

    def get_device(self, device_id: int) -> Dict[str, Any]:
        """
        Get device by ID.

        Args:
            device_id: Device ID

        Returns:
            Device dictionary
        """
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
        logging.info(f"Fetching addresses for device ID {device_id}...")
        result = self._make_request("GET", f"devices/{device_id}/addresses/")
        return result if isinstance(result, list) else []

    def get_device_subnets(self, device_id: int) -> List[Dict[str, Any]]:
        """
        Get all subnets associated with a device.

        Args:
            device_id: Device ID

        Returns:
            List of subnet dictionaries
        """
        logging.info(f"Fetching subnets for device ID {device_id}...")
        result = self._make_request("GET", f"devices/{device_id}/subnets/")
        return result if isinstance(result, list) else []

    # ========== VLANS ==========

    def get_all_vlans(self) -> List[Dict[str, Any]]:
        """
        Get all VLANs.

        Returns:
            List of VLAN dictionaries
        """
        logging.info("Fetching all VLANs...")
        result = self._make_request("GET", "vlan/")
        return result if isinstance(result, list) else []

    def get_vlan(self, vlan_id: int) -> Dict[str, Any]:
        """
        Get VLAN by ID.

        Args:
            vlan_id: VLAN ID

        Returns:
            VLAN dictionary
        """
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
        logging.info(f"Fetching subnets for VLAN ID {vlan_id}...")
        result = self._make_request("GET", f"vlan/{vlan_id}/subnets/")
        return result if isinstance(result, list) else []

    # ========== VRFs ==========

    def get_all_vrfs(self) -> List[Dict[str, Any]]:
        """
        Get all VRFs.

        Returns:
            List of VRF dictionaries
        """
        logging.info("Fetching all VRFs...")
        result = self._make_request("GET", "vrf/")
        return result if isinstance(result, list) else []

    def get_vrf(self, vrf_id: int) -> Dict[str, Any]:
        """
        Get VRF by ID.

        Args:
            vrf_id: VRF ID

        Returns:
            VRF dictionary
        """
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
        logging.info(f"Fetching subnets for VRF ID {vrf_id}...")
        result = self._make_request("GET", f"vrf/{vrf_id}/subnets/")
        return result if isinstance(result, list) else []

    # ========== L2 DOMAINS ==========

    def get_all_l2domains(self) -> List[Dict[str, Any]]:
        """
        Get all L2 domains.

        Returns:
            List of L2 domain dictionaries
        """
        logging.info("Fetching all L2 domains...")
        result = self._make_request("GET", "l2domains/")
        return result if isinstance(result, list) else []

    def get_l2domain(self, domain_id: int) -> Dict[str, Any]:
        """
        Get L2 domain by ID.

        Args:
            domain_id: L2 domain ID

        Returns:
            L2 domain dictionary
        """
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
        logging.info(f"Fetching VLANs for L2 domain ID {domain_id}...")
        result = self._make_request("GET", f"l2domains/{domain_id}/vlans/")
        return result if isinstance(result, list) else []

    # ========== TAGS ==========

    def get_all_tags(self) -> List[Dict[str, Any]]:
        """
        Get all address tags.

        Returns:
            List of tag dictionaries
        """
        logging.info("Fetching all tags...")
        result = self._make_request("GET", "tools/tags/")
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
        logging.info("Fetching all addresses from all subnets...")
        all_addresses = []
        subnets = self.get_all_subnets()

        for subnet in subnets:
            subnet_id = subnet.get("id")
            if subnet_id:
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

        logging.info(f"Retrieved {len(all_addresses)} total addresses")
        return all_addresses
