import asyncio
import aiohttp
import datetime
import logging
import math
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
from globals import SCANNERS, SCAN_JOBS, NAMESPACES, STATE, logger
from scanner import Scanner, Scan_Jobs
from tools import list_scanners, pick_best_xaddr, calc_w3c_duration
#import re
from email import message_from_bytes
from email.policy import default

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
        SCANNERS[tf_g_uuid].model = md_elem.text.strip()

    # SerialNumber
    sn_elem = root.find(".//wsdp:SerialNumber", NAMESPACES)
    if sn_elem is not None:
        SCANNERS[tf_g_uuid].serial = sn_elem.text.strip()

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
    logger.debug(f"   ---> SN: {SCANNERS[tf_g_uuid].serial}")
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
            SCANNERS[subscr_uuid].subscription_timeout = calc_w3c_duration(expires_elem.text.strip())
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


# ---------------- parse Scan available ----------------
def parse_notify_msg(notifier_uuid, xml):
    """
    Parse ScanAvailableEvent and update scanner state.

    Args:
        notifier_uuid (str): URL path (/uuid) belongs to a scanners uuid, this is the notifier_uuid
        xml (str): SOAP Notify payload (string)
    """
    logger.info(f"[PARSE:notify] parsing an event for {SCANNERS[notifier_uuid].friendly_name or notifier_uuid} @ {SCANNERS[notifier_uuid].ip}")
    logger.debug(f"   XML:\n{xml}")

    try:
        root = ET.fromstring(xml)
    except ET.ParseError as e:
        logger.error(f"[PARSE:notify] XML ParseError:\n{e}")
        return None

    subscr_identifier_elem = root.find(".//wse:Identifier", NAMESPACES)
    if subscr_identifier_elem is not None and subscr_identifier_elem.text:
        subscr_identifier = subscr_identifier_elem.text.strip()
        if subscr_identifier.startswith("urn:"):
            subscr_identifier = subscr_identifier.replace("urn:", "")
        if subscr_identifier.startswith("uuid:"):
            subscr_identifier = subscr_identifier.replace("uuid:", "")
    
    action_elem = root.find(".//wsa:Action", NAMESPACES)
    if action_elem is not None and action_elem.text:
        action = action_elem.text.split("/")[-1]  # → "Hello|Bye|Probe"

    client_context_elem = root.find(".//wscn:ClientContext", NAMESPACES)
    if client_context_elem is not None and client_context_elem.text:
        client_context = client_context_elem.text.strip()

    scanjob_identifier_elem = root.find(".//wscn:ScanIdentifier", NAMESPACES)
    if scanjob_identifier_elem is not None and scanjob_identifier_elem.text:
        scanjob_identifier = scanjob_identifier_elem.text.strip()
    
    input_source_elem = root.find(".//wscn:InputSource", NAMESPACES)
    if input_source_elem is not None and input_source_elem.text:
        input_source = input_source_elem.text.strip()

    logger.debug(f"   --->        Notify UUID: {notifier_uuid}")
    logger.debug(f"   --->   *Subscription ID: {subscr_identifier}")
    logger.debug(f"   --->             Action: {action}")
    logger.debug(f"   --->    *Client Context: {client_context}")
    logger.debug(f"   ---> Scanjob Identifier: {scanjob_identifier}")
    logger.debug(f"   --->       Input Source: {input_source}")

    # Neuen Auftrag zum Abholen in SCAN_JOBS[] hinterlegen
    if action == "ScanAvailableEvent":
        if scanjob_identifier not in SCAN_JOBS:
            logger.info(f"+++   surprising News, it seems Scanner {SCANNERS[notifier_uuid].friendly_name or notifier_uuid} @ {SCANNERS[notifier_uuid].ip} has a document for us to scan. Let's go and grab it !   +++")
            SCAN_JOBS[scanjob_identifier] = Scan_Jobs(scanjob_identifier, notifier_uuid, input_source)         # ==> hier wird der Task erstellt für um das Ticket und das Bild abzuholen
            SCANNERS[notifier_uuid].update()
        else:
            logger.info(f"the job that should be added [{scanjob_identifier}] is still in the list")
            return scanjob_identifer    # or return NONE?
    else:
        logger.warning(f"Scanner {SCANNERS[notifier_uuid].friendly_name or notifier_uuid} @ {SCANNERS[notifier_uuid].ip} notified the unrecognized action {action}")
        return None

    return scanjob_identifier
    
# ---------------- Status Parser ----------------
def parse_get_scanner_elements_state(scanjob_identifier, xml):
    logger.info(f"[PARSE:gse_state] parsing scanners state for {SCANNERS[SCAN_JOBS[scanjob_identifier].scan_from_uuid].friendly_name or SCAN_JOBS[scanjob_identifier].scan_from_uuid} @ {SCANNERS[SCAN_JOBS[scanjob_identifier].scan_from_uuid].ip}")
    logger.debug(f"   XML:\n{xml}")

    try:
        root = ET.fromstring(xml)
    except ET.ParseError as e:
        logger.error(f"[PARSE:def_ticket] XML ParseError:\n{e}")
        return False

    #check for ElementData true !!
    data_valid_elem = root.find(".//wscn:ElementData", NAMESPACES)
    if data_valid_elem is not None:
        data_valid = data_valid_elem.attrib.get("Valid", "").strip().lower()
        logger.debug(f" data_valid: {data_valid}")
        if data_valid != "true":
            SCAN_JOBS[scanjob_identifier].state = STATE.SCAN_FAILED
            return False
    
    state_elem = root.find(".//wscn:ScannerState", NAMESPACES)
    if state_elem is not None and state_elem.text:
        state = state_elem.text.strip().lower()
        logger.info(f"   ---> state: {state}")
        if state != "idle":
            SCAN_JOBS[scanjob_identifier].state = STATE.SCAN_FAILED
            return False

    return True



# ---------------- Scanner Configuration Parser ----------------
def parse_get_scanner_elements_configuration(scanjob_identifier, xml):
    logger.info(f"[PARSE:scan_config] parsing scanners configuration, explicit for maxWidth and maxHeight for {SCANNERS[SCAN_JOBS[scanjob_identifier].scan_from_uuid].friendly_name or SCAN_JOBS[scanjob_identifier].scan_from_uuid} @ {SCANNERS[SCAN_JOBS[scanjob_identifier].scan_from_uuid].ip}")
    logger.debug(f"   XML:\n{xml}")

    try:
        root = ET.fromstring(xml)
    except ET.ParseError as e:
        logger.error(f"[PARSE:scan_config] XML ParseError:\n{e}")
        return False

    #check for ElementData true !!
    data_valid_elem = root.find(".//wscn:ElementData", NAMESPACES)
    if data_valid_elem is not None:
        data_valid = data_valid_elem.attrib.get("Valid", "").strip().lower()
        logger.debug(f" data_valid: {data_valid}")
        if data_valid != "true":
            SCAN_JOBS[scanjob_identifier].state = STATE.SCAN_FAILED
            return False

    width_elem = root.find(".//wscn:PlatenMaximumSize/wscn:Width", NAMESPACES)
    if width_elem is not None and width_elem.text:
        width = str(math.floor(int(width_elem.text.strip()) / 10) * 10)
        SCAN_JOBS[scanjob_identifier].DocPar_InputWidth = width
        SCAN_JOBS[scanjob_identifier].DocPar_RegionWidth = width
        logger.debug(f" input_width_elem: {SCAN_JOBS[scanjob_identifier].DocPar_InputWidth}")
        logger.debug(f" region_width_elem: {SCAN_JOBS[scanjob_identifier].DocPar_RegionWidth}")

    height_elem = root.find(".//wscn:PlatenMaximumSize/wscn:Height", NAMESPACES)
    if height_elem is not None and height_elem.text:
        height = str(math.floor(int(height_elem.text.strip()) / 10) * 10)
        SCAN_JOBS[scanjob_identifier].DocPar_InputHeight = height
        SCAN_JOBS[scanjob_identifier].DocPar_RegionHeight = height
        logger.debug(f" input_height_elem: {SCAN_JOBS[scanjob_identifier].DocPar_InputHeight}")
        logger.debug(f" region_height_elem: {SCAN_JOBS[scanjob_identifier].DocPar_RegionHeight}")

    return True


# ---------------- Default Ticket Parser ----------------
def parse_get_scanner_elements_default_ticket(scanjob_identifier, xml):
    logger.info(f"[PARSE:def_ticket] parsing default Ticket for {SCANNERS[SCAN_JOBS[scanjob_identifier].scan_from_uuid].friendly_name or SCAN_JOBS[scanjob_identifier].scan_from_uuid} @ {SCANNERS[SCAN_JOBS[scanjob_identifier].scan_from_uuid].ip}")
    logger.debug(f"   XML:\n{xml}")

    try:
        root = ET.fromstring(xml)
    except ET.ParseError as e:
        logger.error(f"[PARSE:def_ticket] XML ParseError:\n{e}")
        return False

    #check for ElementData true !!
    data_valid_elem = root.find(".//wscn:ElementData", NAMESPACES)
    if data_valid_elem is not None:
        data_valid = data_valid_elem.attrib.get("Valid", "").strip().lower()
        logger.debug(f" data_valid: {data_valid}")
        if data_valid != "true":
            SCAN_JOBS[scanjob_identifier].state = STATE.SCAN_FAILED
            return False
    
    format_elem = root.find(".//wscn:Format", NAMESPACES)
    if format_elem is not None and format_elem.text:
        SCAN_JOBS[scanjob_identifier].DocPar_FileFormat =  format_elem.text.strip()
        logger.debug(f" format: {SCAN_JOBS[scanjob_identifier].DocPar_FileFormat}")

    images_to_transfer_elem = root.find(".//wscn:ImagesToTransfer", NAMESPACES)
    if images_to_transfer_elem is not None and images_to_transfer_elem.text:
        SCAN_JOBS[scanjob_identifier].DocPar_ImagesToTransfer = images_to_transfer_elem.text.strip()
        logger.debug(f" images_to_transfer: {SCAN_JOBS[scanjob_identifier].DocPar_ImagesToTransfer}")

    input_source_elem = root.find(".//wscn:InputSource", NAMESPACES)
    if input_source_elem is not None and input_source_elem.text:
        SCAN_JOBS[scanjob_identifier].DocPar_InputSource = input_source_elem.text.strip()
        logger.debug(f" InputSource: {SCAN_JOBS[scanjob_identifier].DocPar_InputSource}")

#    diese zwei sind an dieser Stelle leer, wie sieht das mit anderen Scannern aus? Deswegen hole ich mir das aus GetScannerElements/Configuration und runde ab, dafür die XML-Ausgabe wieder auf INFO stellen...
#
#    input_width_elem = root.find(".//wscn:InputMediaSize/wscn:Width", NAMESPACES)
#    if input_width_elem is not None and input_width_elem.text:
#        SCAN_JOBS[scanjob_identifier].DocPar_InputWidth = input_width_elem.text.strip()
#        logger.info(f" InputWidth: {SCAN_JOBS[scanjob_identifier].DocPar_InputWidth}")
#
#    input_height_elem = root.find(".//wscn:InputMediaSize/wscn:Height", NAMESPACES)
#    if input_height_elem is not None and input_height_elem.text:
#        SCAN_JOBS[scanjob_identifier].DocPar_InputHeight = input_height_elem.text.strip()
#        logger.info(f" InputHeight: {SCAN_JOBS[scanjob_identifier].DocPar_InputHeight}")

    contrast_elem = root.find(".//wscn:Contrast", NAMESPACES)
    if contrast_elem is not None and contrast_elem.text:
        SCAN_JOBS[scanjob_identifier].DocPar_ExposureContrast = contrast_elem.text.strip()
        logger.debug(f" contrast: {SCAN_JOBS[scanjob_identifier].DocPar_ExposureContrast}")

    brightness_elem = root.find(".//wscn:Brightness", NAMESPACES)
    if brightness_elem is not None and brightness_elem.text:
        SCAN_JOBS[scanjob_identifier].DocPar_ExposureBrightness = brightness_elem.text.strip()
        logger.debug(f" brightness: {SCAN_JOBS[scanjob_identifier].DocPar_ExposureBrightness}")

    scaling_width_elem = root.find(".//wscn:ScalingWidth", NAMESPACES)
    if scaling_width_elem is not None and scaling_width_elem.text:
        SCAN_JOBS[scanjob_identifier].DocPar_ScalingWidth = scaling_width_elem.text.strip()
        logger.debug(f" scaling_width: {SCAN_JOBS[scanjob_identifier].DocPar_ScalingWidth}")

    scaling_height_elem = root.find(".//wscn:ScalingHeight", NAMESPACES)
    if scaling_height_elem is not None and scaling_height_elem.text:
        SCAN_JOBS[scanjob_identifier].DocPar_ScalingHeight = scaling_height_elem.text.strip()
        logger.debug(f" scaling_height: {SCAN_JOBS[scanjob_identifier].DocPar_ScalingHeight}")

    rotation_elem = root.find(".//wscn:Rotation", NAMESPACES)
    if rotation_elem is not None and rotation_elem.text:
        SCAN_JOBS[scanjob_identifier].DocPar_Rotation = rotation_elem.text.strip()
        logger.debug(f" rotation: {SCAN_JOBS[scanjob_identifier].DocPar_Rotation}")

    pixels_per_line_elem = root.find(".//wscn:PixelsPerLine", NAMESPACES)
    if pixels_per_line_elem is not None and pixels_per_line_elem.text:
        SCAN_JOBS[scanjob_identifier].DocPar_PixelsPerLine = pixels_per_line_elem.text.strip()
        logger.debug(f" *PixelsPerLine: {SCAN_JOBS[scanjob_identifier].DocPar_PixelsPerLine}")

    number_of_lines_elem = root.find(".//wscn:NumberOfLines", NAMESPACES)
    if number_of_lines_elem is not None and number_of_lines_elem.text:
        SCAN_JOBS[scanjob_identifier].DocPar_NumberOfLines = number_of_lines_elem.text.strip()
        logger.debug(f" *number_of_lines: {SCAN_JOBS[scanjob_identifier].DocPar_NumberOfLines}")

    bytes_per_line_elem = root.find(".//wscn:BytesPerLine", NAMESPACES)
    if bytes_per_line_elem is not None and bytes_per_line_elem.text:
        SCAN_JOBS[scanjob_identifier].DocPar_BytesPerLine = bytes_per_line_elem.text.strip()
        logger.debug(f" *bytes_per_line: {SCAN_JOBS[scanjob_identifier].DocPar_BytesPerLine}")

    x_offset_elem = root.find(".//wscn:ScanRegionXOffset", NAMESPACES)
    if x_offset_elem is not None and x_offset_elem.text:
        SCAN_JOBS[scanjob_identifier].DocPar_RegionXOffset = x_offset_elem.text.strip()
        logger.debug(f" x_offset: {SCAN_JOBS[scanjob_identifier].DocPar_RegionXOffset}")

    y_offset_elem = root.find(".//wscn:ScanRegionYOffset", NAMESPACES)
    if y_offset_elem is not None and y_offset_elem.text:
        SCAN_JOBS[scanjob_identifier].DocPar_RegionYOffset = y_offset_elem.text.strip()
        logger.debug(f" y_offset: {SCAN_JOBS[scanjob_identifier].DocPar_RegionYOffset}")

#    diese zwei sind an dieser Stelle leer, wie sieht das mit anderen Scannern aus? Deswegen hole ich mir das aus GetScannerElements/Configuration und runde ab, dafür die XML-Ausgabe wieder auf INFO stellen...
#
#    region_width_elem = root.find(".//wscn:ScanRegionWidth", NAMESPACES)
#    if region_width_elem is not None and region_width_elem.text:
#        region_width = region_width_elem.text.strip()
#        SCAN_JOBS[scanjob_identifier].DocPar_RegionWidth = region_width
#        logger.info(f" region_width: {SCAN_JOBS[scanjob_identifier].DocPar_RegionWidth}")
#
#    region_height_elem = root.find(".//wscn:ScanRegionHeight", NAMESPACES)
#    if region_height_elem is not None and region_height_elem.text:
#        region_height = region_height_elem.text.strip()
#        SCAN_JOBS[scanjob_identifier].DocPar_RegionHeight = region_height
#        logger.info(f" region_height: {SCAN_JOBS[scanjob_identifier].DocPar_RegionHeight}")

    color_processing_elem = root.find(".//wscn:ColorProcessing", NAMESPACES)
    if color_processing_elem is not None and color_processing_elem.text:
        SCAN_JOBS[scanjob_identifier].DocPar_ColorProcessing = color_processing_elem.text.strip()
        logger.debug(f" color_processing: {SCAN_JOBS[scanjob_identifier].DocPar_ColorProcessing}")

    resolution_width_elem = root.find(".//wscn:Resolution/wscn:Width", NAMESPACES)
    if resolution_width_elem is not None and resolution_width_elem.text:
        SCAN_JOBS[scanjob_identifier].DocPar_ResolutionWidth = resolution_width_elem.text.strip()
        logger.debug(f" resolution_width: {SCAN_JOBS[scanjob_identifier].DocPar_ResolutionWidth}")

    resolution_height_elem = root.find(".//wscn:Resolution/wscn:Height", NAMESPACES)
    if resolution_height_elem is not None and resolution_height_elem.text:
        SCAN_JOBS[scanjob_identifier].DocPar_ResolutionHeight =  resolution_height_elem.text.strip()
        logger.debug(f" resolution_height: {SCAN_JOBS[scanjob_identifier].DocPar_ResolutionHeight}")

    return True

# ---------------- parse create Scan Job Response ----------------
#async def parse_create_scan_job_response(scan_identifier, xml: str) -> bool:
def parse_create_scan_job(scanjob_identifier, xml: str):
    """Parst die Antwort vom Scanner und speichert Werte in SCAN_JOBS."""
    logger.info(f"[PARSE:sj_ticket] parsing ticket request for {scanjob_identifier} from {SCANNERS[SCAN_JOBS[scanjob_identifier].scan_from_uuid].friendly_name or SCAN_JOBS[scanjob_identifier].scan_from_uuid} @ {SCANNERS[SCAN_JOBS[scanjob_identifier].scan_from_uuid].ip}")
    logger.debug(f"   XML:\n{xml}")

    try:
        root = ET.fromstring(xml)
    except ET.ParseError as e:
        logger.error(f"[PARSE:sj_ticket] failed to parse CreateScanJobResponse:\n{e}")
        SCAN_JOBS[scanjob_identifier].state = STATE.SCAN_FAILED
        return False

    # JobID
    job_id = ""
    job_id_elem = root.find(".//wscn:JobId", NAMESPACES)
    if job_id_elem is not None and job_id_elem.text:
        job_id = job_id_elem.text.strip()
        SCAN_JOBS[scanjob_identifier].job_id = job_id
    else:
        logger.warning(f" cannot extract JobId from Response")
        SCAN_JOBS[scanjob_identifier].state = STATE.SCAN_FAILED
        return False

    # JobToken
    job_token = ""
    job_token_elem = root.find(".//wscn:JobToken", NAMESPACES)
    if job_token_elem is not None and job_token_elem.text:
        SCAN_JOBS[scanjob_identifier].job_token = job_token_elem.text.strip()
    else:
        logger.warning(f" cannot extract JobToken from Response")
        SCAN_JOBS[scanjob_identifier].state = STATE.SCAN_FAILED
        return False

    # FileFormat
    format = ""
    format_elem = root.find(".//wscn:Format", NAMESPACES)
    if format_elem is not None and format_elem.text:
        SCAN_JOBS[scanjob_identifier].DocPar_FileFormat = format_elem.text.strip()
    else:
        logger.warning(f" cannot extract Format from Response")
        SCAN_JOBS[scanjob_identifier].state = STATE.SCAN_FAILED
        return False

    # PixelsPerLine
    pixels_per_line = ""
    pixels_per_line_elem = root.find(".//wscn:PixelsPerLine", NAMESPACES)
    if pixels_per_line_elem is not None and pixels_per_line_elem.text:
        SCAN_JOBS[scanjob_identifier].DocPar_PixelsPerLine = pixels_per_line_elem.text.strip()
    else:
        logger.warning(f" cannot extract Pixels per Line from Response")
#        SCAN_JOBS[scanjob_identifier].state = STATE.SCAN_FAILED
#        return False

    # NumberOfLines
    number_of_lines = ""
    number_of_lines_elem = root.find(".//wscn:NumberOfLines", NAMESPACES)
    if number_of_lines_elem is not None and number_of_lines_elem.text:
        SCAN_JOBS[scanjob_identifier].DocPar_NumberOfLines = number_of_lines_elem.text.strip()
    else:
        logger.warning(f" cannot extract Number of Lines from Response")
#        SCAN_JOBS[scanjob_identifier].state = STATE.SCAN_FAILED
#        return False

    # BytesPerLine
    bytes_per_line = ""
    bytes_per_line_elem = root.find(".//wscn:BytesPerLine", NAMESPACES)
    if bytes_per_line_elem is not None and bytes_per_line_elem.text:
        SCAN_JOBS[scanjob_identifier].DocPar_BytesPerLine = bytes_per_line_elem.text.strip()
    else:
        logger.warning(f" cannot extract Bytes per Line from Response")
#        SCAN_JOBS[scanjob_identifier].state = STATE.SCAN_FAILED
#        return False

    logger.debug(f"   --->     JobId: {SCAN_JOBS[scanjob_identifier].job_id}")
    logger.debug(f"   --->  JobToken: {SCAN_JOBS[scanjob_identifier].job_token}")
    logger.debug(f"   --->    Format: {SCAN_JOBS[scanjob_identifier].DocPar_FileFormat}")
    logger.debug(f"   --->   PxPLine: {SCAN_JOBS[scanjob_identifier].DocPar_PixelsPerLine}")
    logger.debug(f"   --->  NbrLines: {SCAN_JOBS[scanjob_identifier].DocPar_NumberOfLines}")
    logger.debug(f"   --->Bytes/Line: {SCAN_JOBS[scanjob_identifier].DocPar_BytesPerLine}")

    return True


#    Parse multipart/related RetrieveImageResponse from scanner.
#    Returns: (soap_xml: str, image_bytes: bytes or None)
# ------------------------------- extract image from retrieved content ----------------------------------------------------
def parse_retrieve_image(scanjob_identifier, data, content_type: str):
    logger.info(f"[PARSE:rtrv_img] parsing {len(data)} bytes for scan job {scanjob_identifier}")
    logger.info(f" content-type: {content_type}")
    logger.info(f"      content:\n{data[:1500]}")

    SCAN_JOBS[scanjob_identifier].state = STATE.SCAN_EXTRACT_IMG

    if not content_type.lower().startswith("multipart/"):
        logger.error(f"[PARSE:rtrv_img] content-type not multipart: {content_type}")
        return False

    # Den vollständigen MIME-Datensatz künstlich zusammensetzen:
    mime_data = f"Content-Type: {content_type}\r\nMIME-Version: 1.0\r\n\r\n".encode("utf-8") + data

    # multipart nach email-ähnlicher Struktur parsen
    msg = message_from_bytes(mime_data, policy=default)

    # Fallback falls boundary nicht automatisch erkannt wird:
    if not msg.is_multipart():
        logger.error(f"[PARSE:rtrv_img] received data is no multipart response")
        logger.info(f"first 200 bytes: {data[:200]!r}")
        SCAN_JOBS[scanjob_identifier].state = STATE.SCAN_FAILED
        return False

    for part in msg.iter_parts():
        content_type = part.get_content_type()
        content_id = part.get("Content-ID")
        logger.info(f"searching ID: {content_id}")
        logger.info(f"Content-Type: {content_type}")

        # Wir suchen den Binärteil — meist image/jpeg oder application/pdf
        if content_type == "application/xop+xml":
            logger.info("   Found XML metadata part")
            metadata = part.get_payload(decode=True)
            logger.info(f" metadata: {metadata}")
        elif content_type in ("application/binary", "image/jpeg", "image/png", "image/tiff", "application/pdf"):
            logger.info(f" content type found: {content_type} (ID={content_id})")
#            SCAN_JOBS[scanjob_identifier].document = part.get_content()
            SCAN_JOBS[scanjob_identifier].document = part.get_payload(decode=True)
            logger.info(f" saved {len(SCAN_JOBS[{scanjob_identifier}].document)} Bytes in SCAN_JOBS[{scanjob_identifier}].document")
            logger.info(f" first 50 bytes: {SCAN_JOBS[{scanjob_identifier}].document[:200]!r}")
            return True
        else:
            logger.error(f"[PARSE:rtrv_img] could not find any of binary|image|pdf in stream for scan job ID {scanjob_identifier}")
            SCAN_JOBS[scanjob_identifier].state = STATE.SCAN_FAILED
            return False



def _parse_retrieve_image(scanjob_identifier, data, content_type: str):
    """
    Parse multipart/related RetrieveImageResponse from scanner.
    Returns: (soap_xml: str, image_bytes: bytes or None)
    """
    logger.info(f"[PARSE:rtrv_img] parsing {len(data)} bytes for scan job {scanjob_identifier}")
    logger.info(f" content-type: {content_type}")
    logger.info(f"      content:\n{data[:1500]}")

    
    # Boundary extrahieren
    m = re.search(r'boundary="?([^";]+)"?', content_type, re.IGNORECASE)
    if not m:
        logger.warning(" No MIME boundary found in Content-Type")
        return None, None
    boundary = m.group(1).encode()

    parts = data.split(b"--" + boundary)
    xml = None
    image_bytes = None
    image_content_id = None

    logger.info(" Logpoint A")
    
    for p in parts:
        if not p.strip() or p.startswith(b"--"):
            continue

        logger.info(" Logpoint B")
    
        headers, _, data = p.partition(b"\r\n\r\n")
        headers_decoded = headers.decode(errors="ignore")

        if "application/xop+xml" in headers_decoded or "application/soap+xml" in headers_decoded:
            xml = re.sub(rb"^[0-9a-fA-F]+\r\n", b"", data.strip())
            xml = xml.strip(b"\r\n0\r\n")
        elif "application/binary" in headers_decoded:
            image_bytes = data.strip()
            m_id = re.search(r"Content-ID:\s*<([^>]+)>", headers_decoded)
            if m_id:
                image_content_id = m_id.group(1)

    logger.info(" Logpoint C")
    # SOAP optional parsen (nur Logging)
    if soap_xml:
        logger.info(" Logpoint D")
        try:
            root = ET.fromstring(soap_xml)
#            ns = {
#                "soap": "http://www.w3.org/2003/05/soap-envelope",
#                "wscn": "http://schemas.microsoft.com/windows/2006/08/wdp/scan",
#                "xop": "http://www.w3.org/2004/08/xop/include"
#            }
            href = root.find(".//xop:Include", NAMESPACES)
            logger.info(" Logpoint E")
            if href is not None:
                cid = href.attrib.get("href", "").replace("cid:", "")
                logger.info(" Logpoint F")
                if image_content_id and cid != image_content_id:
                    logger.info(" Logpoint A")
                    logger.warning(f"[PARSER] Mismatch CID: {cid} != {image_content_id}")
        except Exception as e:
            logger.warning(f"[PARSER] Could not parse SOAP XML: {e}")

    logger.info(" Logpoint G")
    return soap_xml.decode("utf-8", errors="ignore") if soap_xml else None, image_bytes



#
#
# **************************************************
# **************** END OF PARSE.PY  ****************
