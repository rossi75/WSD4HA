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
#from globals import SCANNERS, list_scanners, NAMESPACES, STATE, LOG_LEVEL
from globals import SCANNERS, NAMESPACES, STATE, LOG_LEVEL
from pathlib import Path
from scanner import Scanner
from templates import TEMPLATE_SOAP_PROBE, TEMPLATE_SOAP_TRANSFER_GET
from scan_job import fetch_scanned_document
from tools import list_scanners, pick_best_xaddr

#logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')
#logging.basicConfig(level=logging.LOG_LEVEL, format='[%(levelname)s] %(message)s')
logging.basicConfig(level=LOG_LEVEL, format='[%(levelname)s] %(message)s')
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
    logger.info(f"{datetime.datetime.now():%Y-%m-%d %H:%M:%S} [PARSE:parse_probe] parsing probe from {SCANNERS[probed_uuid].friendly_name or probed_uuid} @ {SCANNERS[probed_uuid].ip}")
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


        # neuer oder vorhandener Endpoint?
        if probe_uuid not in SCANNERS:
            SCANNERS[probe_uuid] = Scanner(uuid=probe_uuid, ip=SCANNERS[probed_uuid].ip, xaddr=xaddr)
            SCANNERS[probe_uuid].state = STATE.PROBE_PARSED                       # das neue Gerät > hat die Probe bestanden, wird nun weiter konnektiert
            SCANNERS[probed_uuid].update()                                    # das alte Gerät > ist weiterhin online, wird nicht mehr bearbeitet
            marry_endpoints(probed_uuid, probe_uuid)
            logger.info(f"[WSD:probe_parser] Discovered new scanner endpoint with {probe_uuid} @ {SCANNERS[probed_uuid].ip} as child from {probed_uuid}")
        else:
            if SCANNERS[probed_uuid].subscription_last_seen is not None:
                SCANNERS[probed_uuid].update()
                logger.debug(f"   ===>  already found a subscription for {SCANNERS[probed_uuid].friendly_name} @ {SCANNERS[probed_uuid].ip}, no need to ask for more details")
            else:
                SCANNERS[probed_uuid].xaddr = xaddr
                SCANNERS[probed_uuid].state = STATE.PROBE_PARSED
            logger.debug(f"[WSD:probe_parser] Updated scanner {SCANNERS[probed_uuid].friendly_name or probed_uuid} @ {SCANNERS[probed_uuid].ip}   --->   xaddr: {xaddr}")

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

    # Maunfacturer
    mf_elem = root.find(".//wsdp:Manufacturer", NAMESPACES)
    if mf_elem is not None:
        SCANNERS[tf_g_uuid].manufacturer = mf_elem.text.strip()

    # Model
    md_elem = root.find(".//wsdp:ModelName", NAMESPACES)
    if md_elem is not None:
        SCANNERS[tf_g_uuid].serial_number = md_elem.text.strip()

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

    logger.debug(f"   ---> FN: {SCANNERS[tf_g_uuid].friendly_name}")
    logger.debug(f"   ---> SN: {SCANNERS[tf_g_uuid].serial_number}")
    logger.debug(f"   ---> FW: {SCANNERS[tf_g_uuid].firmware}")
    logger.debug(f"   ---> MF: {SCANNERS[tf_g_uuid].manufacturer}")
    logger.debug(f"   ---> MD: {SCANNERS[tf_g_uuid].model}")

    SCANNERS[tf_g_uuid].state = STATE.TF_GET_PARSED

# ---------------- Subscribe Parser ----------------
def parse_subscribe(subscr_uuid, xml_body):
    """
    Parse SubscribeResponse and extract:
        expires_sec, subscription_id, subscription_ref, destination_token
    """
    logger.info(f"{datetime.datetime.now():%Y-%m-%d %H:%M:%S} [PARSE:parse_subscribe] parsing SubscribeResponse for {SCANNERS[subscr_uuid].friendly_name} at {SCANNERS[subscr_uuid].ip}")
    logger.debug(f"XML:\n{xml_body}")

    match SCANNERS[subscr_uuid].state:
        case STATE.SUBSCRIBING_SCAN_AVAIL_EVT:
            SCANNERS[subscr_uuid].state = STATE.CHK_SCAN_AVAIL_EVT
        case STATE.RNW_1_2_PENDING:
            SCANNERS[subscr_uuid].state = STATE.SUBSCR_RNW_1_2_CHK
        case STATE.RNW_3_4_PENDING:
            SCANNERS[subscr_uuid].state = STATE.SUBSCR_RNW_3_4_CHK
        case _: # Sammelfall
            logger.warning(f"I was called with state {SCANNERS[subscr_uuid].state.value}, but cannot handle this")
            SCANNERS[subscr_uuid].state = STATE.ERROR

    try:
        root = ET.fromstring(xml_body)
    except ET.ParseError as e:
        logger.error(f"[PARSE:subscr] Error while parsing subscribe response: {e}")
        SCANNERS[subscr_uuid].state = STATE.ERROR
        return None

    # Expires (Duration -> Sekunden)
    expires_elem = root.find(".//wse:Expires", NAMESPACES)
    if expires_elem is not None and expires_elem.text:
        logger.debug(f"   ---> expires_elem: {expires_elem.text.strip()}")
        try:
            SCANNERS[subscr_uuid].subscription_timeout = parse_w3c_duration(expires_elem.text.strip())
            SCANNERS[subscr_uuid].update_subscription()
        except Exception as e:
            logger.warning(f"[PARSE:subscr] Could not parse Expires: {e}")
            SCANNERS[subscr_uuid].state = STATE.ERROR
            return None

    # Subscription ID (Header Identifier)
    subscr_id = ""
    subscr_id_elem = root.find(".//soap:Header/wse:Identifier", NAMESPACES)
    if subscr_id_elem is not None and subscr_id_elem.text:
        subscr_id = subscr_id_elem.text.strip()
        logger.debug(f"   ---> subscr_id_elem: {subscr_id}")
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
        logger.debug(f"   ---> ref_ui_elem: {ref_id}")
        SCANNERS[subscr_uuid].subscription_ref = ref_id

    # DestinationToken
    dest_token_elem = root.find(".//wscn:DestinationToken", NAMESPACES)
    if dest_token_elem is not None and dest_token_elem.text:
        SCANNERS[subscr_uuid].destination_token = dest_token_elem.text.strip()
        logger.debug(f"   ---> dest_token_elem: {SCANNERS[subscr_uuid].destination_token}")

    logger.debug(f"   --->        UUID: {subscr_uuid}")
    logger.debug(f"   --->     timeout: {SCANNERS[subscr_uuid].subscription_timeout}")
    logger.debug(f"   --->   last_seen: {SCANNERS[subscr_uuid].subscription_last_seen}")
    logger.debug(f"   --->   subscr_id: {SCANNERS[subscr_uuid].subscription_id}")
    logger.debug(f"   --->      ref_id: {SCANNERS[subscr_uuid].subscription_ref}")
    logger.debug(f"   --->  dest_token: {SCANNERS[subscr_uuid].destination_token}")

    # SCANNERS[subscr_uuid].state = STATE.SUBSCRIBED_SCAN_AVAIL_EVT
    match SCANNERS[subscr_uuid].state:
        case STATE.CHK_SCAN_AVAIL_EVT:
            SCANNERS[subscr_uuid].update()
        case STATE.SUBSCR_RNW_1_2_CHK:
            SCANNERS[subscr_uuid].update()
        case STATE.SUBSCR_RNW_3_4_CHK:
            SCANNERS[subscr_uuid].update()
        case STATE.ERROR:
            SCANNERS[subscr_uuid].state = STATE.ERROR
        case _: # Sammelfall
            logger.error(f"finished function [PARSE:subscribe] with state {SCANNERS[subscr_uuid].state}, but don't know what to do with it (should never reach this point !)")
            SCANNERS[subscr_uuid].state = STATE.ERROR

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

    return seconds

# ---------------- parse Scan available ----------------
def parse_scan_available(notify_uuid, xml):
    """
    Parse ScanAvailableEvent and update scanner state.

    Args:
        notify_uuid (str): UUID from URL path (/uuid)
        xml (str): SOAP Notify payload (string)
    """
    logger.info(f"{datetime.datetime.now():%Y-%m-%d %H:%M:%S} [PARSE:scan_available] parsing ScanAvailableEvent for {notify_uuid}")
    logger.info(f"   XML:\n{xml}")

    try:
        root = ET.fromstring(xml)
    except ET.ParseError as e:
        logger.error(f"[PARSE:scan_available] XML ParseError: {e}")
        return

    subscr_identifier_elem = root.find(".//wse:Identifier", NAMESPACES)
    if subscr_identifier_elem is not None and subscr_identifier_elem.text:
        subscr_identifier = subscr_identifier_elem.text.strip()
        if subscr_identifier.startswith("urn:"):
            subscr_identifier = subscr_identifier.replace("urn:", "")
        if subscr_identifier.startswith("uuid:"):
            subscr_identifier = subscr_identifier.replace("uuid:", "")

    action_elem = root.find(".//wsa:Action", NAMESPACES)
    if action_elem is not None and action_elem.text:
        action = action_elem.text.strip()

    scan_identifier_elem = root.find(".//wscn:ScanIdentifier", NAMESPACES)
    if scan_identifier_elem is not None and scan_identifier_elem.text:
        scan_identifier = scan_identifier_elem.text.strip()
    
    input_source_elem = root.find(".//wscn:InputSource", NAMESPACES)
    if input_source_elem is not None and input_source_elem.text:
        input_source = input_source_elem.text.strip()

    # umrechnen von notify_uuid zu SCANNERS[uuid]
    

    logger.info(f"   --->     Notify UUID: {notify_uuid}")
    logger.info(f"   ---> Subscription ID: {subscr_identifier}")
    logger.info(f"   --->          Action: {action}")
    logger.info(f"   --->         Scan ID: {scan_identifier}")
    logger.info(f"   --->    Input Source: {input_source}")


    # Neuen Auftrag zum Abholen in SCANNER_JOBS[] hinterlegen
    if subscr_identifier in SCANNERS:
        s = SCANNER_JOBS[subscr_identifier]
#        s.last_scan_id = scan_identifier
#        s.last_scan_source = input_source
#        s.last_scan_time = datetime.datetime.now().replace(microsecond=0)
        logger.info(f"+++ surprising News, it seems Scanner {s.friendly_name} @ {s.ip} has a document for us. Let's go and grab it ! +++")
        SCANNERS[notify_uuid].update()
        SCANNERS[s.uuid].state = STATE.SCAN_AVAILABLE
        asyncio.create_task(fetch_scanned_document(s.uuid, scan_identifier))
    else:
        logger.info(f"could not find {notify_uuid} in the list of known Scanners")

    # was machen wir jetzt mit der Info dass es ggf einen neuen Scan gibt?
    # auf jeden Fall hat er sich gemeldet, also merken wir uns das iwie


# **************** END OF PARSE.PY  ****************
