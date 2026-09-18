#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Create custom index for Suricata security events in Sycope.

This script creates a custom index in Sycope for storing Suricata security events.
It connects to the Sycope API and sets up the necessary database schema with
predefined fields for Suricata EVE JSON log data.

The installer creates an index with fields for:
- Common network event data (IPs, ports, protocols, timestamps)
- Alert-specific fields (signature ID, severity, action, etc.)
- Anomaly-specific fields (event type, category)
- Client/server role determination fields
- TLS fields introduced/extended in Suricata 8.0 (ja4, client_alpns, subjectaltname)
- With --profile all-protocols: metadata fields for smb, krb5, dhcp, snmp,
  dcerpc, ssh, smtp, rdp, sip, nfs, ftp, tftp, telnet, ldap, pop3

Script version: 3.0
Tested on Sycope 3.1
"""

import argparse
import logging
import os
import sys

import requests

# Add parent directory to path for importing sycope modules
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from sycope.api import SycopeApi
from sycope.config import load_config
from sycope.exceptions import SycopeError
from sycope.logging import setup_logging, suppress_ssl_warnings

logger = logging.getLogger(__name__)

# Configuration file path
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_FILE = os.path.join(SCRIPT_DIR, "config.json")

# Suricata field definitions for the custom index (basic profile).
# These fields map to the data structure of Suricata EVE JSON logs.
BASIC_FIELDS = [
    # Common network event fields
    {"name": "timestamp", "type": "long", "description": "Event timestamp", "displayName": "Timestamp"},
    {"name": "flow_id", "type": "long", "description": "Suricata flow ID", "displayName": "Flow ID"},
    {"name": "in_iface", "type": "string", "description": "Interface name", "displayName": "Interface"},
    {"name": "event_type", "type": "string", "description": "Type of event", "displayName": "Event Type"},
    {"name": "src_ip", "type": "ip4", "description": "Source IP address", "displayName": "Source IP"},
    {"name": "src_port", "type": "int", "description": "Source port", "displayName": "Source Port"},
    {
        "name": "dest_ip",
        "type": "ip4",
        "description": "Destination IP address",
        "displayName": "Destination IP",
    },
    {
        "name": "dest_port",
        "type": "int",
        "description": "Destination port",
        "displayName": "Destination Port",
    },
    {
        "name": "clientIp",
        "type": "ip4",
        "description": "Client IP address (determined by port)",
        "displayName": "Client IP",
    },
    {
        "name": "clientPort",
        "type": "int",
        "description": "Client port (higher port number)",
        "displayName": "Client Port",
    },
    {
        "name": "serverIp",
        "type": "ip4",
        "description": "Server IP address (determined by port)",
        "displayName": "Server IP",
    },
    {
        "name": "serverPort",
        "type": "int",
        "description": "Server port (lower port number)",
        "displayName": "Server Port",
    },
    {"name": "proto", "type": "string", "description": "Layer 4 protocol", "displayName": "Protocol"},
    # Alert-specific fields (from Suricata alert events)
    {
        "name": "alert_action",
        "type": "string",
        "description": "Alert action",
        "displayName": "Suricata Alert Action",
    },
    {"name": "alert_gid", "type": "int", "description": "Generator ID", "displayName": "Suricata Alert GID"},
    {"name": "alert_signature_id", "type": "int", "description": "Signature ID", "displayName": "Sig ID"},
    {"name": "alert_rev", "type": "int", "description": "Signature revision", "displayName": "Sig Rev"},
    {
        "name": "event_signature",
        "type": "string",
        "description": "Signature text",
        "displayName": "Signature",
    },
    {
        "name": "event_category",
        "type": "string",
        "description": "Signature category",
        "displayName": "Category",
    },
    {"name": "alert_severity", "type": "int", "description": "Severity level", "displayName": "Severity"},
    # Additional protocol information
    {
        "name": "app_proto",
        "type": "string",
        "description": "Application protocol",
        "displayName": "App Proto",
    },
    # TLS fields (Suricata 8.0; None on 7.0.x sources)
    {"name": "tls_ja4", "type": "string", "description": "JA4 TLS client fingerprint", "displayName": "JA4"},
    {
        "name": "tls_client_alpns",
        "type": "string",
        "description": "Client-offered ALPN protocols (comma-separated)",
        "displayName": "Client ALPNs",
    },
    {
        "name": "tls_subjectaltname",
        "type": "string",
        "description": "Certificate subjectAltName entries (comma-separated)",
        "displayName": "Subject Alt Name",
    },
]

# Additional fields for --profile all-protocols. Column names match the
# path keys used in eve_processor.py's column_map - do not rename without
# also updating the mapping there, dashboards bind to these names.
PROTOCOL_FIELDS = [
    # SMB
    {"name": "smb_command", "type": "string", "description": "SMB command", "displayName": "SMB Command"},
    {"name": "smb_status", "type": "string", "description": "SMB status", "displayName": "SMB Status"},
    {"name": "smb_dialect", "type": "string", "description": "SMB dialect", "displayName": "SMB Dialect"},
    {"name": "smb_session_id", "type": "long", "description": "SMB session ID", "displayName": "SMB Session ID"},
    {"name": "smb_tree_id", "type": "long", "description": "SMB tree ID", "displayName": "SMB Tree ID"},
    {"name": "smb_access", "type": "string", "description": "SMB access mask", "displayName": "SMB Access"},
    {"name": "smb_filename", "type": "string", "description": "SMB filename", "displayName": "SMB Filename"},
    # Kerberos
    {"name": "krb5_msg_type", "type": "string", "description": "Kerberos message type", "displayName": "KRB5 Msg Type"},
    {"name": "krb5_cname", "type": "string", "description": "Kerberos client name", "displayName": "KRB5 CName"},
    {"name": "krb5_realm", "type": "string", "description": "Kerberos realm", "displayName": "KRB5 Realm"},
    {"name": "krb5_sname", "type": "string", "description": "Kerberos service name", "displayName": "KRB5 SName"},
    {"name": "krb5_encryption", "type": "string", "description": "Kerberos encryption type", "displayName": "KRB5 Encryption"},
    {
        "name": "krb5_weak_encryption",
        "type": "string",
        "description": "Whether weak Kerberos encryption was used",
        "displayName": "KRB5 Weak Encryption",
    },
    # DHCP
    {"name": "dhcp_type", "type": "string", "description": "DHCP message type", "displayName": "DHCP Type"},
    {"name": "dhcp_client_mac", "type": "string", "description": "DHCP client MAC", "displayName": "DHCP Client MAC"},
    {"name": "dhcp_assigned_ip", "type": "ip4", "description": "DHCP assigned IP", "displayName": "DHCP Assigned IP"},
    {"name": "dhcp_hostname", "type": "string", "description": "DHCP client hostname", "displayName": "DHCP Hostname"},
    # SNMP
    {"name": "snmp_version", "type": "int", "description": "SNMP version", "displayName": "SNMP Version"},
    {"name": "snmp_pdu_type", "type": "string", "description": "SNMP PDU type", "displayName": "SNMP PDU Type"},
    {"name": "snmp_community", "type": "string", "description": "SNMP community string", "displayName": "SNMP Community"},
    # DCERPC
    {"name": "dcerpc_request", "type": "string", "description": "DCERPC request", "displayName": "DCERPC Request"},
    {"name": "dcerpc_call_id", "type": "long", "description": "DCERPC call ID", "displayName": "DCERPC Call ID"},
    {
        "name": "dcerpc_interfaces",
        "type": "string",
        "description": "DCERPC interfaces (comma-separated)",
        "displayName": "DCERPC Interfaces",
    },
    # SSH
    {"name": "ssh_client_software", "type": "string", "description": "SSH client software version", "displayName": "SSH Client SW"},
    {"name": "ssh_server_software", "type": "string", "description": "SSH server software version", "displayName": "SSH Server SW"},
    # SMTP
    {"name": "smtp_helo", "type": "string", "description": "SMTP HELO/EHLO value", "displayName": "SMTP HELO"},
    {"name": "smtp_mail_from", "type": "string", "description": "SMTP MAIL FROM", "displayName": "SMTP Mail From"},
    {
        "name": "smtp_rcpt_to",
        "type": "string",
        "description": "SMTP RCPT TO (comma-separated)",
        "displayName": "SMTP Rcpt To",
    },
    # RDP
    {"name": "rdp_protocol", "type": "string", "description": "RDP negotiated protocol", "displayName": "RDP Protocol"},
    {"name": "rdp_cookie", "type": "string", "description": "RDP cookie", "displayName": "RDP Cookie"},
    # SIP
    {"name": "sip_method", "type": "string", "description": "SIP method", "displayName": "SIP Method"},
    {"name": "sip_uri", "type": "string", "description": "SIP request URI", "displayName": "SIP URI"},
    # NFS
    {"name": "nfs_procedure", "type": "string", "description": "NFS procedure", "displayName": "NFS Procedure"},
    {"name": "nfs_filename", "type": "string", "description": "NFS filename", "displayName": "NFS Filename"},
    # FTP
    {"name": "ftp_command", "type": "string", "description": "FTP command", "displayName": "FTP Command"},
    {"name": "ftp_reply", "type": "string", "description": "FTP reply text", "displayName": "FTP Reply"},
    # TFTP
    {"name": "tftp_packet", "type": "string", "description": "TFTP packet type", "displayName": "TFTP Packet"},
    {"name": "tftp_file", "type": "string", "description": "TFTP filename", "displayName": "TFTP File"},
    # Telnet
    {"name": "telnet_data", "type": "string", "description": "Telnet data", "displayName": "Telnet Data"},
    # LDAP
    {"name": "ldap_operation", "type": "string", "description": "LDAP request operation", "displayName": "LDAP Operation"},
    {"name": "ldap_bind_name", "type": "string", "description": "LDAP bind request name", "displayName": "LDAP Bind Name"},
    {
        "name": "ldap_bind_sasl_mechanism",
        "type": "string",
        "description": "LDAP bind SASL mechanism",
        "displayName": "LDAP SASL Mechanism",
    },
    {
        "name": "ldap_bind_result_code",
        "type": "string",
        "description": "LDAP bind response result code",
        "displayName": "LDAP Bind Result Code",
    },
    # POP3
    {"name": "pop3_command", "type": "string", "description": "POP3 command", "displayName": "POP3 Command"},
]


def build_fields(profile):
    """Return the field list for the given install profile."""
    if profile == "all-protocols":
        return BASIC_FIELDS + PROTOCOL_FIELDS
    return BASIC_FIELDS


def parse_args():
    parser = argparse.ArgumentParser(description="Create the Suricata custom index in Sycope.")
    parser.add_argument(
        "--profile",
        choices=["basic", "all-protocols"],
        default="basic",
        help=(
            "Field set to install. 'basic' (default) keeps the existing common/alert/anomaly/tls "
            "fields - no behavior change for existing installs. 'all-protocols' additionally creates "
            "columns for smb, krb5, dhcp, snmp, dcerpc, ssh, smtp, rdp, sip, nfs, ftp, tftp, telnet, "
            "ldap, pop3."
        ),
    )
    return parser.parse_args()


def main() -> None:
    """Create the Suricata custom index."""
    args = parse_args()

    # Load configuration first to get log_level
    try:
        cfg = load_config(
            CONFIG_FILE,
            required_fields=["sycope_host", "sycope_login", "sycope_pass", "index_name"],
        )
    except Exception as e:
        # Setup basic logging to report the error
        setup_logging("install.log")
        logging.error(f"Failed to load config: {e}")
        sys.exit(1)

    # Setup environment with log_level from config
    suppress_ssl_warnings()
    setup_logging("install.log", log_level=cfg.get("log_level", "info"))

    logger.debug("=" * 60)
    logger.debug("Suricata Install script starting")
    logger.debug(f"Script directory: {SCRIPT_DIR}")
    logger.debug(f"Config file: {CONFIG_FILE}")
    logger.debug(f"Profile: {args.profile}")
    logger.debug("=" * 60)

    fields = build_fields(args.profile)

    # Log field definitions
    logger.debug(f"Index field definitions ({len(fields)} fields):")
    for field in fields:
        logger.debug(f"  {field['name']}: type={field['type']}, displayName={field.get('displayName')}")

    logger.debug("Configuration loaded successfully")
    logger.debug(f"  Sycope host: {cfg['sycope_host']}")
    logger.debug(f"  Index name: {cfg['index_name']}")
    logger.debug(f"  API base: {cfg.get('api_base', '/npm/api/v1/')}")

    logging.info(f"Loaded configuration from {CONFIG_FILE}")
    logging.info(f"Using profile '{args.profile}' ({len(fields)} fields)")

    # Connect to Sycope and create index
    logger.debug("Creating HTTP session...")
    with requests.Session() as session:
        session.headers.update({"Content-Type": "application/json"})
        logger.debug("Session headers set")

        try:
            logger.debug("Authenticating to Sycope API...")
            api = SycopeApi(
                session=session,
                host=cfg["sycope_host"],
                login=cfg["sycope_login"],
                password=cfg["sycope_pass"],
                api_endpoint=cfg.get("api_base", "/npm/api/v1/"),
            )
            logger.debug("Sycope authentication successful")

            logging.info(f"Creating Suricata index: {cfg['index_name']}")
            logger.debug("Index parameters:")
            logger.debug(f"  Name: {cfg['index_name']}")
            logger.debug("  Rotation: daily")
            logger.debug(f"  Fields count: {len(fields)}")

            api.create_index(cfg["index_name"], fields, rotation="daily")
            logging.info("Index created successfully")
            logger.debug("Index creation complete")

        except SycopeError as e:
            logging.error(f"Sycope API error: {e}")
            logger.debug(f"Sycope exception: {type(e).__name__}: {e}")
            if hasattr(e, "status_code"):
                logger.debug(f"  Status code: {e.status_code}")
            if hasattr(e, "response"):
                logger.debug(f"  Response: {e.response}")
            sys.exit(1)
        finally:
            logger.debug("Logging out from Sycope...")
            api.log_out()
            logger.debug("Script complete")


if __name__ == "__main__":
    main()
