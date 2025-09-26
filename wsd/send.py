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
from config import OFFLINE_TIMEOUT, LOCAL_IP, HTTP_PORT, FROM_UUID, DISPLAY
from globals import SCANNERS, list_scanners, NAMESPACES, STATE, USER_AGENT
from pathlib import Path
from scanner import Scanner
from templates import TEMPLATE_SOAP_PROBE, TEMPLATE_SOAP_TRANSFER_GET, TEMPLATE_SUBSCRIBE_SAE, TEMPLATE_SUBSCRIBE_RENEW
from parse import parse_wsd_packet, parse_probe, parse_transfer_get, parse_subscribe

logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')
logger = logging.getLogger("wsd-addon")

# ---------------- Send Scanner Probe ----------------
async def send_probe(scanner):
    logger.info(f"{datetime.datetime.now():%Y-%m-%d %H:%M:%S} [SEND:send_probe] sending probe for {scanner.uuid} @ {scanner.ip}")

    scanner.state = STATE.PROBING
    msg_id = uuid.uuid4()
    xml = TEMPLATE_SOAP_PROBE.format(msg_id=msg_id)

    headers = {
        "Content-Type": "application/soap+xml",
        #"User-Agent": "WSD4HA",
#        "User-Agent": "WSDAPI",
        "User-Agent": USER_AGENT
    }

    url = f"http://{scanner.ip}:80/StableWSDiscoveryEndpoint/schemas-xmlsoap-org_ws_2005_04_discovery"

    logger.info(f"   ---> URL: {url}")
    logger.debug(f"   ---> XML:\n{xml}")

    body = ""

    async with aiohttp.ClientSession() as session:
        try:
            async with session.post(url, data=xml, headers=headers, timeout=5) as resp:
                if resp.status == 200:
                    body = await resp.text()
                else:
                    logger.error(f"Probe failed with status {resp.status}")
                    scanner.state = STATE.ABSENT
        except Exception as e:
            logger.error(f"   ---> Probe fehlgeschlagen bei {url}: {e}")
            scanner.state = STATE.ABSENT

    logger.debug(f"ProbeMatch von {scanner.ip}:\n{body}")
    parse_probe(body, scanner.uuid)

    logger.debug(f"   ---> Statuscode: {resp.status}")

# ---------------- Send Transfer_Get ----------------
async def send_transfer_get(tf_g_uuid: str):
    logger.info(f"{datetime.datetime.now():%Y-%m-%d %H:%M:%S} [SEND:transfer_get] sending Transfer/Get to {tf_g_uuid} @ {SCANNERS[tf_g_uuid].ip}")
    
    SCANNERS[tf_g_uuid].state = STATE.TF_GET_PENDING
    msg_id = uuid.uuid4()

    xml = TEMPLATE_SOAP_TRANSFER_GET.format(
        to_device_uuid=tf_g_uuid,
        msg_id=msg_id,
        from_uuid=FROM_UUID
    )

    headers = {
        "Content-Type": "application/soap+xml",
#        "User-Agent": "WSDAPI",
        "User-Agent": USER_AGENT,
    }

    url = SCANNERS[tf_g_uuid].xaddr  # z.B. http://192.168.0.3:8018/wsd

    logger.debug(f"   --->    FROM: {FROM_UUID}")
    logger.debug(f"   --->      TO: {tf_g_uuid}")
    logger.debug(f"   --->  MSG_ID: {msg_id}")
    logger.debug(f"   --->     URL: {url}")
    logger.debug(f"   --->     XML:\n{xml}")

    body = ""

    async with aiohttp.ClientSession() as session:
        try:
            async with session.post(url, data=xml, headers=headers, timeout=5) as resp:
                if resp.status == 200:
                    body = await resp.text()
                else:
                    SCANNERS[tf_g_uuid].state = STATE.ERROR
                    logger.error(f"[WSD:transfer_get] TransferGet failed with Statuscode {resp.status}")
                    return None
        except Exception as e:
            logger.error(f"[WSD:transfer_get] failed for {SCANNERS[tf_g_uuid].uuid}: {e}")
            SCANNERS[tf_g_uuid].state = STATE.ERROR
            return None
 
    logger.debug(f"TransferGet von {SCANNERS[tf_g_uuid].ip}:\n{body}")
    parse_transfer_get(body, tf_g_uuid)

# ---------------- Subscribe ScanAvailableEvent ----------------
async def send_subscr_ScanAvailableEvent(sae_uuid: str):
    # to_device_uuid = scanners endpoint UUID
    # msg_id = Message ID
    # xaddr = serviceadress  ==>  <wsa:To>http://192.168.0.3:8018/wsd/scan</wsa:To>
    # from_uuid = WSD4HAs UUID
    # EndTo_addr = adress that needs to be reachable by the scanner  ==>  <wsa:Address>http://192.168.0.1:5357/6ccf7716-4dc8-47bf-aca4-5a2ae5a959ca</wsa:Address>
    # scan_to_name = Option selected by the user to start the scanning  ==>  "Scan to Home Assistant"
    # Ref_ID = one more senseless ID  ==>  <wse:Identifier>urn:uuid:680be7cf-bc5a-409d-ad1d-4d6d96b5cb4f</wse:Identifier>
    logger.info(f"{datetime.datetime.now():%Y-%m-%d %H:%M:%S} [SEND:subscr_sae] subscribing ScanAvailableEvent to {sae_uuid} @ {SCANNERS[sae_uuid].ip}")
    
    SCANNERS[sae_uuid].state = STATE.SUBSCRIBING_SCAN_AVAIL_EVT
    msg_id = uuid.uuid4()
    ref_id = uuid.uuid4()

    xml = TEMPLATE_SUBSCRIBE_SAE.format(
        to_device_uuid = sae_uuid,
        msg_id = msg_id,
        from_uuid = FROM_UUID,
        xaddr = SCANNERS[sae_uuid].xaddr,
        EndTo_addr = "http://192.168.0.10:5357/asdjkfhewjkhauiscndiausdnue",
        scan_to_name = DISPLAY,
        Ref_ID = ref_id,
    )

    headers = {
        "Content-Type": "application/soap+xml",
#        "User-Agent": "WSDAPI",
        "User-Agent": USER_AGENT,
    }

    url = SCANNERS[sae_uuid].xaddr  # z.B. http://192.168.0.3:8018/wsd

    logger.debug(f"   --->      TO: {sae_uuid}")
    logger.debug(f"   --->  MSG_ID: {msg_id}")
    logger.debug(f"   --->    FROM: {FROM_UUID}")
    logger.info(f"   --->  End_To: {EndTo_addr}")
    logger.info(f"   --->    NAME: {DISPLAY}")
    logger.info(f"   --->  REF_ID: {ref_id}")
    logger.info(f"   --->     URL: {url}")
    logger.info(f"   --->     XML:\n{xml}")

    body = ""

    async with aiohttp.ClientSession() as session:
        try:
            async with session.post(url, data=xml, headers=headers, timeout=5) as resp:
                if resp.status == 200:
                    body = await resp.text()
                else:
                    SCANNERS[sae_uuid].state = STATE.ERROR
                    logger.error(f"[SEND:sae] Subscribe to ScanAvailableEvents failed with Statuscode {resp.status}")
                    return None
        except Exception as e:
            logger.error(f"[SEND:sae] failed for {SCANNERS[tf_g_uuid].uuid}: {e}")
            SCANNERS[tf_g_uuid].state = STATE.ERROR
            return None
 
#    logger.debug(f"received ScanAvailableEvents from {SCANNERS[sae_uuid].ip} as XML:\n{body}")
    parse_subscribe(sae_uuid, body)

# ---------------- Subscribe ScanAvailableEvent ----------------
async def send_subscr_renew(renew_uuid: str):

    # to_device_uuid = scanners endpoint UUID
    # msg_id = Message ID
    # xaddr = serviceadress  ==>  <wsa:To>http://192.168.0.3:8018/wsd/scan</wsa:To>
    # from_uuid = WSD4HAs UUID
    # EndTo_addr = adress that needs to be reachable by the scanner  ==>  <wsa:Address>http://192.168.0.1:5357/6ccf7716-4dc8-47bf-aca4-5a2ae5a959ca</wsa:Address>
    # scan_to_name = Option selected by the user to start the scanning  ==>  "Scan to Home Assistant"
    # Ref_ID = one more senseless ID  ==>  <wse:Identifier>urn:uuid:680be7cf-bc5a-409d-ad1d-4d6d96b5cb4f</wse:Identifier>
    logger.info(f"{datetime.datetime.now():%Y-%m-%d %H:%M:%S} [SEND:subscr_rnw] renewing subscrition for {renew_uuid} @ {SCANNERS[renew_uuid].ip}")
    
    SCANNERS[renew_uuid].state = STATE.SUBSCRIBING_SCAN_AVAIL_EVT
    msg_id = uuid.uuid4()
    ref_id = uuid.uuid4()

    xml = TEMPLATE_SUBSCRIBE_RENEW.format(
        to_device_uuid = renew_uuid,
        msg_id = msg_id,
        from_uuid = FROM_UUID,
        xaddr = SCANNERS[renew_uuid].xaddr,
        EndTo_addr = "http://192.168.0.10:5357/asdjkfhewjkhauiscndiausdnue",
        scan_to_name = DISPLAY,
#        Ref_ID = "680be7cf-bc5a-409d-ad1d-4d6d96b5cb4f",
        Ref_ID = ref_id,
    )

    headers = {
        "Content-Type": "application/soap+xml",

        "User-Agent": "WSDAPI",
    }

    url = SCANNERS[renew_uuid].xaddr  # z.B. http://192.168.0.3:8018/wsd

    logger.debug(f"   --->      TO: {renew_uuid}")
    logger.debug(f"   --->  MSG_ID: {msg_id}")
    logger.debug(f"   --->    FROM: {FROM_UUID}")
    #logger.debug(f"   --->  End_To: {msg_id}")
    logger.debug(f"   --->    NAME: {DISPLAY}")
    #logger.debug(f"   --->  REF_ID: {msg_id}")
    logger.info(f"   --->     URL: {url}")
    logger.info(f"   --->     XML:\n{xml}")

    body = ""

    async with aiohttp.ClientSession() as session:
        try:
            async with session.post(url, data=xml, headers=headers, timeout=5) as resp:
                if resp.status == 200:
                    body = await resp.text()
                else:
                    SCANNERS[renew_uuid].state = STATE.ERROR
                    logger.error(f"[SEND:sae] Subscribe to ScanAvailableEvents failed with Statuscode {resp.status}")
                    return None
        except Exception as e:
            logger.error(f"[SEND:sae] failed for {SCANNERS[renew_uuid].uuid}: {e}")
            SCANNERS[renew_uuid].state = STATE.ERROR
            return None
 
#    logger.debug(f"received ScanAvailableEvents from {SCANNERS[sae_uuid].ip} as XML:\n{body}")
    parse_subscribe(renew_uuid, body)

