import asyncio
import aiohttp
import datetime
import logging
import os
import re
import socket
import subprocess
import sys
import time
import threading
import uuid
import xml.etree.ElementTree as ET
from datetime import timedelta
from config import OFFLINE_TIMEOUT, LOCAL_IP, HTTP_PORT, FROM_UUID
from globals import SCANNERS, list_scanners, NAMESPACES, STATE
from pathlib import Path
from scanner import Scanner
from templates import TEMPLATE_SOAP_PROBE, TEMPLATE_SOAP_TRANSFER_GET

logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')
logger = logging.getLogger("wsd-addon")

# ---------------- WSD SOAP Parser ----------------
def parse_wsd_packet(data: bytes):
    try:
        xml = ET.fromstring(data.decode("utf-8", errors="ignore"))
        action = xml.find(".//wsa:Action", NAMESPACES)
        uuid = xml.find(".//wsa:Address", NAMESPACES)
        return {
            "action": action.text if action is not None else None,
            "uuid": uuid.text if uuid is not None else None,
        }
    except Exception as e:
        logger.debug(f"[WSD] Error while parsing: {e}")
        return None


# ---------------- Probe Parser ----------------
def parse_probe(xml: str, probed_uuid: str):
    """
    Parse ProbeMatch response and update/create Scanner objects.

    Args:
        xml (str): SOAP XML response as string
        scanners (dict): Dictionary {uuid: Scanner}
        
    """
    logger.info(f"{datetime.datetime.now():%Y-%m-%d %H:%M:%S} [PARSE:parse_probe] parsing probe from {probed_uuid} @ {SCANNERS[probed_uuid].ip}")
    logger.debug(f"XML:\n{xml}")
    
    SCANNERS[probed_uuid].state = STATE.PROBE_PARSING
   
    try:
        root = ET.fromstring(xml)
    except ET.ParseError as e:
        logger.error(f"[PARSE:probe_parser] XML ParseError: {e}")
        SCANNERS[probed_uuid].state = STATE.ERROR
        return

    for pm in root.findall(".//wsd:ProbeMatch", NAMESPACES):

        # UUID (without urn:uuid:)
        probe_uuid = None
        uuid_elem = pm.find(".//wsa:Address", NAMESPACES)
        if uuid_elem is not None and uuid_elem.text:
            probe_uuid = uuid_elem.text.strip()
            if probe_uuid.startswith("urn:uuid:"):
                probe_uuid = probe_uuid.replace("urn:uuid:", "")
            else:
                probe_uuid = uuid_text

        # Nur Scanner akzeptieren
        types = None
        types_elem = pm.find(".//wsd:Types", NAMESPACES)
        types = types_elem.text.strip().split()
        if not any("ScanDeviceType" in t for t in types):
            logger.info(f"[WSD:probe_parser] Skipping non-scanner device {probe_uuid}")
            continue

        # die Serviceadresse finden
        xaddr = None
        xaddrs_elem = pm.find(".//wsd:XAddrs", NAMESPACES)
        xaddr = pick_best_xaddr(xaddrs_elem.text.strip())

        if probe_uuid is None or types is None or xaddr is None:
            logger.warning(f"[PARSE:parse_probe] Incomplete ProbeMatch, skipping UUID {probe_uuid}")
            logger.warning(f"   --->  UUID: {probe_uuid}")
            logger.warning(f"   ---> TYPES: {types}")
            logger.warning(f"   ---> XADDR: {xaddr}")
            SCANNERS[probed_uuid].state = STATE.ERROR
            continue


        # neuer oder vorhandener Scanner?
        if probe_uuid not in SCANNERS:
            SCANNERS[probe_uuid] = Scanner(uuid=probe_uuid, ip=SCANNERS[probed_uuid].ip, xaddr=xaddr)
            SCANNERS[probe_uuid].state = STATE.PROBE_PARSED                       # das neue Gerät > hat die Probe bestanden, wird nun weiter konnektiert
            SCANNERS[probed_uuid].state = STATE.ONLINE                                    # das alte Gerät > ist weiterhin online, wird nicht mehr bearbeitet
            marry_endpoints(probed_uuid, probe_uuid)
            logger.info(f"[WSD:probe_parser] Discovered new scanner endpoint with {probe_uuid} @ {SCANNER[probed_uuid].ip} as child from {probed_uuid}")
        else:
            SCANNERS[probed_uuid].xaddr = xaddr
            SCANNERS[probed_uuid].state = STATE.PROBE_PARSED
            logger.info(f"[WSD:probe_parser] Updated scanner {probed_uuid} -> {xaddr}")

    list_scanners()

# ---------------- Transfer/GET Parser ----------------
def parse_transfer_get(xml_body, tf_g_uuid):
    logger.info(f"{datetime.datetime.now():%Y-%m-%d %H:%M:%S} [PARSE:parse_t_g] parsing transfer_get from {SCANNERS[tf_g_uuid].friendly_name} @ {SCANNERS[tf_g_uuid].ip}")
    logger.debug(f"XML:\n{xml_body}")

    SCANNERS[tf_g_uuid].state = STATE.TF_GET_PARSING

    try:
        root = ET.fromstring(xml_body)
    except Exception as e:
        logger.warning(f"[PARSE] Error while parsing transfer_get: {e}")
        SCANNERS[tf_g_uuid].state = STATE.ERROR
        return None

    # FriendlyName
    fn_elem = root.find(".//wsdp:FriendlyName", NAMESPACES)
    if fn_elem is not None:
        SCANNERS[tf_g_uuid].friendly_name = fn_elem.text.strip()

    # SerialNumber
    sn_elem = root.find(".//wsdp:SerialNumber", NAMESPACES)
    if sn_elem is not None:
        SCANNERS[tf_g_uuid].serial_number = sn_elem.text.strip()

    # Firmware
    fw_elem = root.find(".//wsdp:FirmwareVersion", NAMESPACES)
    if fw_elem is not None:
        SCANNERS[tf_g_uuid].firmware = fw_elem.text.strip()

    # Hosted Services (Scan, Print, …)
    SCANNERS[tf_g_uuid].services = {}
    for hosted in root.findall(".//wsdp:Hosted", NAMESPACES):
        addr_elem = hosted.find(".//wsa:Address", NAMESPACES)
        type_elem = hosted.find(".//wsdp:Types", NAMESPACES)
        if addr_elem is not None and type_elem is not None:
            addr = addr_elem.text.strip()
            types = type_elem.text.strip()
            logger.info(f" TYPES: {types}")
            if "ScannerServiceType" in types:
                SCANNERS[tf_g_uuid].xaddr = addr
            logger.info(f"  ADDR: {SCANNERS[tf_g_uuid].xaddr}")
                
#                SCANNERS[tf_g_uuid].services["scan"] = addr

    logger.info(f"   ---> FN: {SCANNERS[tf_g_uuid].friendly_name}")
    logger.info(f"   ---> SN: {SCANNERS[tf_g_uuid].serial_number}")
    logger.info(f"   ---> FW: {SCANNERS[tf_g_uuid].firmware}")

    SCANNERS[tf_g_uuid].state = STATE.TF_GET_PARSED

# ---------------- Subscribe Parser ----------------
def parse_subscribe(subscr_uuid, xml_body):
    """
    Parse SubscribeResponse and extract:
        expires_sec, subscription_id, subscription_ref, destination_token
    """
    logger.info(f"{datetime.datetime.now():%Y-%m-%d %H:%M:%S} [PARSE:parse_subscribe] parsing SubscribeResponse for {SCANNERS[subscr_uuid].friendly_name} at {SCANNERS[subscr_uuid].ip}")
    logger.info(f"XML:\n{xml_body}")

    SCANNERS[subscr_uuid].state = STATE.CHK_SCAN_AVAIL_EVT

    try:
        root = ET.fromstring(xml_body)
    except ET.ParseError as e:
        logger.warning(f"[PARSE:subscr] Error while parsing subscribe response: {e}")
        SCANNERS[subscr_uuid].state = STATE.ERROR
        return None

    # Expires (Duration -> Sekunden)
    expires_elem = root.find(".//wse:Expires", NAMESPACES)
    logger.info(f"   ---> expires_elem: {expires_elem.text.strip()}")
    if expires_elem is not None and expires_elem.text:
        try:
            SCANNERS[subscr_uuid].subscription_timeout = expires_elem.text.strip()
            SCANNERS[subscr_uuid].subscription_expires = datetime.datetime.now().replace(microsecond=0) + parse_w3c_duration(expires_elem.text.strip())
        except Exception as e:
            logger.warning(f"[PARSE:subscr] Could not parse Expires: {e}")
            SCANNERS[subscr_uuid].state = STATE.ERROR
            return None

    # Subscription ID (Header Identifier)
    subscr_id = ""
    subscr_id_elem = root.find(".//soap:Header/wse:Identifier", NAMESPACES)
    if subscr_id_elem is not None and subscr_id_elem.text:
        subscr_id = subscr_id_elem.text.strip()
        if subscr_id.startswith("urn:"):
            subscr_id = subscr_id.replace("urn:", "")
        if subscr_id.startswith("uuid:"):
            subscr_id = subscr_id.replace("uuid:", "")
        SCANNERS[subscr_uuid].subscription_id = subscr_id
                
    # ReferenceParameters -> Identifier
    ref_id = ""
    ref_id_elem = root.find(".//wsa:ReferenceParameters/wse:Identifier", NAMESPACES)
    if ref_id_elem is not None and ref_id_elem.text:
        ref_id = ref_id_elem.text.strip()
        logger.info(f"   --->      ref_id: {SCANNERS[subscr_uuid].subscription_ref}")
        if ref_id.startswith("urn:"):
            ref_id = ref_id.replace("urn:", "")
        logger.info(f"   --->      ref_id: {SCANNERS[subscr_uuid].subscription_ref}")
        if ref_id.startswith("uuid:"):
            ref_id = ref_id.replace("uuid:", "")
        logger.info(f"   --->      ref_id: {SCANNERS[subscr_uuid].subscription_ref}")
        SCANNERS[subscr_uuid].subscription_ref = ref_id_elem.text.strip()

    # DestinationToken
    dest_token_elem = root.find(".//wscn:DestinationToken", NAMESPACES)
    if dest_token_elem is not None and dest_token_elem.text:
        SCANNERS[subscr_uuid].destination_token = dest_token_elem.text.strip()

    logger.info(f"   --->        UUID: {subscr_uuid}")
    logger.info(f"   --->     timeout: {SCANNERS[subscr_uuid].subscription_timeout}")
    logger.info(f"   --->     expires: {SCANNERS[subscr_uuid].subscription_expires}")
    logger.info(f"   --->   subscr_id: {SCANNERS[subscr_uuid].subscription_id}")
    logger.info(f"   --->      ref_id: {SCANNERS[subscr_uuid].subscription_ref}")
    logger.info(f"   --->  dest_token: {SCANNERS[subscr_uuid].destination_token}")

    SCANNERS[subscr_uuid].state = STATE.SUBSCRIBED_SCAN_AVAIL_EVT

# ---------------- parse w3c timer ----------------
# parse_w3c_duration("PT1H")   # -> 3600
def parse_w3c_duration(duration: str) -> int:
    """
    Wandelt W3C/ISO8601 Duration (z.B. 'PT1H30M') in Sekunden um.
    Unterstützt Tage, Stunden, Minuten, Sekunden.
    """
    
    logger.debug(f"[PARSE:w3c_dur]   ---> duration: {duration}")
    
    pattern = (
        r'P'                                  # Beginn 'P'
        r'(?:(?P<days>\d+)D)?'                # Tage
        r'(?:T'                               # Beginn Zeitabschnitt
        r'(?:(?P<hours>\d+)H)?'
        r'(?:(?P<minutes>\d+)M)?'
        r'(?:(?P<seconds>\d+)S)?'
        r')?'
    )
    
    m = re.match(pattern, duration)
    if not m:
        return 0
    d = m.groupdict(default='0')
    
    seconds = int(d['days']) * 86400 + int(d['hours']) * 3600 + int(d['minutes']) * 60 + int(d['seconds'])
    
    logger.debug(f"[PARSE:w3c_dur]   ---> d: {d}")
    logger.debug(f"[PARSE:w3c_dur]   ---> seconds: {seconds}")

    return timedelta(seconds = seconds)

# ---------------- Pick Best XADDR from String ----------------
def pick_best_xaddr(xaddrs: str) -> str:
    """
    Wählt aus einer Liste von XAddrs den besten Kandidaten:
    - bevorzugt IPv4
    - ignoriert IPv6, wenn IPv4 vorhanden ist
    - nimmt den Hostnamen, falls keine IP vorhanden ist
    """
    logger.debug(f"{datetime.datetime.now():%Y-%m-%d %H:%M:%S}[WSD:XADDR] received {xaddrs}")
    if not xaddrs:
        return None

    candidates = xaddrs.split()

    ipv4 = None
    hostname = None

    for addr in candidates:
        if addr.startswith("http://["):  
            # IPv6 -> ignorieren
            continue
        elif addr.startswith("http://") and any(c.isdigit() for c in addr.split("/")[2].split(":")[0]):
            # IPv4 gefunden
            ipv4 = addr
        else:
            # vermutlich Hostname
            hostname = addr

    logger.debug(f"[WSD:XADDR] extracted {ipv4 or hostname or None}")
    return ipv4 or hostname or None

