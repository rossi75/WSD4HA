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
#from config import OFFLINE_TIMEOUT, LOCAL_IP, HTTP_PORT, FROM_UUID, DISPLAY, NOTIFY_PORT, get_local_ip
#from globals import SCANNERS, list_scanners, NAMESPACES, STATE, USER_AGENT, LOG_LEVEL
from config import OFFLINE_TIMEOUT, LOCAL_IP, HTTP_PORT, FROM_UUID, DISPLAY, NOTIFY_PORT
from globals import SCANNERS, NAMESPACES, STATE, USER_AGENT, LOG_LEVEL
from parse import parse_wsd_packet, parse_probe, parse_transfer_get, parse_subscribe
from pathlib import Path
from scanner import Scanner
from tools import list_scanners, get_local_ip
from templates import TEMPLATE_SOAP_PROBE, TEMPLATE_SOAP_TRANSFER_GET, TEMPLATE_SUBSCRIBE_SAE, TEMPLATE_SUBSCRIBE_RENEW

#logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')
#logging.basicConfig(level=logging.{LOG_LEVEL}, format='[%(levelname)s] %(message)s')
logging.basicConfig(level=LOG_LEVEL, format='[%(levelname)s] %(message)s')
logger = logging.getLogger("wsd-addon")

# ---------------- Send Scanner Probe ----------------
async def send_probe(probe_uuid: str):
    logger.info(f"{datetime.datetime.now():%Y-%m-%d %H:%M:%S} [SEND:send_probe] sending probe for {SCANNERS[probe_uuid].friendly_name} @ {SCANNERS[probe_uuid].ip}")

    SCANNERS[probe_uuid].state = STATE.PROBING

    msg_id = uuid.uuid4()
    body = ""
    xml = TEMPLATE_SOAP_PROBE.format(msg_id=msg_id)
    headers = {
        "Content-Type": "application/soap+xml",
        "User-Agent": USER_AGENT
    }
    url = f"http://{SCANNERS[probe_uuid].ip}:80/StableWSDiscoveryEndpoint/schemas-xmlsoap-org_ws_2005_04_discovery"

    logger.debug(f"   ---> URL: {url}")
    logger.debug(f"   ---> XML:\n{xml}")

    async with aiohttp.ClientSession() as session:
        try:
            async with session.post(url, data=xml, headers=headers, timeout=5) as resp:
                if resp.status == 200:
                    body = await resp.text()
                else:
                    logger.error(f"Probe failed with status {resp.status}")
                    SCANNERS[uuid].state = STATE.ABSENT
        except Exception as e:
            logger.error(f"   ---> Probe failed at {url}: {e}")
            SCANNERS[probe_uuid].state = STATE.ABSENT

    logger.debug(f"ProbeMatch from {SCANNERS[probe_uuid].ip}:\n{body}")

    parse_probe(body, probe_uuid)


# ---------------- Send Transfer_Get ----------------
async def send_transfer_get(tf_g_uuid: str):
    logger.info(f"{datetime.datetime.now():%Y-%m-%d %H:%M:%S} [SEND:transfer_get] sending Transfer/Get to {tf_g_uuid} @ {SCANNERS[tf_g_uuid].ip}")
    
    SCANNERS[tf_g_uuid].state = STATE.TF_GET_PENDING

    body = ""
    msg_id = uuid.uuid4()
    xml = TEMPLATE_SOAP_TRANSFER_GET.format(
        to_device_uuid=tf_g_uuid,
        msg_id=msg_id,
        from_uuid=FROM_UUID
    )
    headers = {
        "Content-Type": "application/soap+xml",
        "User-Agent": USER_AGENT
    }
    url = SCANNERS[tf_g_uuid].xaddr  # z.B. http://192.168.0.3:8018/wsd

    logger.debug(f"   --->    FROM: {FROM_UUID}")
    logger.debug(f"   --->      TO: {tf_g_uuid}")
    logger.debug(f"   --->  MSG_ID: {msg_id}")
    logger.debug(f"   --->     URL: {url}")
    logger.debug(f"   --->     XML:\n{xml}")

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


###################################################################################
# Subscribe ScanAvailableEvent
# ---------------------------------------------------------------------------------
# Parameters:
# sae_uuis = scanners endpoint UUID
# ---------------------------------------------------------------------------------
async def send_subscription_ScanAvailableEvent(sae_uuid: str):
    logger.info(f"{datetime.datetime.now():%Y-%m-%d %H:%M:%S} [SEND:subscr_sae] subscribing ScanAvailableEvent to {SCANNERS[sae_uuid].friendly_name or sae_uuid} @ {SCANNERS[sae_uuid].ip}")
    
    SCANNERS[sae_uuid].state = STATE.SUBSCRIBING_SCAN_AVAIL_EVT

    body = ""
    msg_id = uuid.uuid4()
    ref_id = uuid.uuid4()
    addr_id = uuid.uuid4()
    url = SCANNERS[sae_uuid].xaddr  # z.B. http://192.168.0.3:8018/wsd
    if SCANNERS[sae_uuid].end_to_addr is None:
#        SCANNERS[sae_uuid].end_to_addr = f"http://192.168.0.10:5357/{addr_id}"
        SCANNERS[sae_uuid].end_to_addr = f"http://{get_local_ip()}:{NOTIFY_PORT}/{addr_id}"
        logger.info(f"created new end_to_addr")
    else:
        logger.info(f"using existing end_to_addr")

    headers = {
        "Content-Type": "application/soap+xml",
        "User-Agent": USER_AGENT
    }
    xml = TEMPLATE_SUBSCRIBE_SAE.format(
        to_device_uuid = sae_uuid,
        msg_id = msg_id,
        from_uuid = FROM_UUID,
        xaddr = SCANNERS[sae_uuid].xaddr,
        EndTo_addr = SCANNERS[sae_uuid].end_to_addr,
        scan_to_name = DISPLAY,
        Ref_ID = ref_id
    )

    logger.debug(f"   --->     URL: {url}")
    logger.debug(f"   --->    FROM: {FROM_UUID}")
    logger.debug(f"   --->      TO: {sae_uuid}")
    logger.debug(f"   --->  MSG_ID: {msg_id}")
    logger.debug(f"   --->  REF_ID: {ref_id}")
    logger.debug(f"   --->  NAMEoD: {DISPLAY}")
    logger.debug(f"   --->  End_To: {SCANNERS[sae_uuid].end_to_addr}")
    logger.debug(f"   --->     XML:\n{xml}")

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
 
    parse_subscribe(sae_uuid, body)

###################################################################################
# Subscription Renew
# ---------------------------------------------------------------------------------
# Parameters:
# renew_uuid = scanners endpoint UUID
# ---------------------------------------------------------------------------------
async def send_subscription_renew(renew_uuid: str):
    logger.info(f"{datetime.datetime.now():%Y-%m-%d %H:%M:%S} [SEND:subscr_rnw] renewing subscription for {SCANNERS[renew_uuid].friendly_name or renew_uuid} @ {SCANNERS[renew_uuid].ip}")
    
    SCANNERS[renew_uuid].state = STATE.SUBSCRIBING_SCAN_AVAIL_EVT

    body = ""
    msg_id = uuid.uuid4()
    ref_id = SCANNERS[renew_uuid].subscription_ref
    EndToAddr = SCANNERS[renew_uuid].end_to_addr
    url = SCANNERS[renew_uuid].xaddr  # z.B. http://192.168.0.3:8018/wsd
    xml = TEMPLATE_SUBSCRIBE_RENEW.format(
        to_device_uuid = renew_uuid,
        msg_id = msg_id,
        from_uuid = FROM_UUID,
        xaddr = SCANNERS[renew_uuid].xaddr,
        EndTo_addr = EndToAddr,
        scan_to_name = DISPLAY,
        Ref_ID = ref_id
    )
    headers = {
        "Content-Type": "application/soap+xml",
        "User-Agent": USER_AGENT
    }

    logger.debug(f"   --->      FROM: {FROM_UUID}")
    logger.debug(f"   --->        TO: {renew_uuid}")
    logger.debug(f"   --->    MSG_ID: {msg_id}")
    logger.debug(f"   ---> subscr_ID: {ref_id}")
    logger.debug(f"   --->    End_To: {EndToAddr}")
    logger.debug(f"   --->       URL: {url}")
    logger.debug(f"   --->       XML:\n{xml}")

    async with aiohttp.ClientSession() as session:
        try:
            async with session.post(url, data=xml, headers=headers, timeout=5) as resp:
                if resp.status == 200:
                    body = await resp.text()
                else:
                    SCANNERS[renew_uuid].state = STATE.ERROR
                    logger.error(f"[SEND:rnw] Renew to ScanAvailableEvents failed with Statuscode {resp.status}")
                    return None
        except Exception as e:
            logger.error(f"[SEND:rnw] failed for {SCANNERS[renew_uuid].uuid}: {e}")
            SCANNERS[renew_uuid].state = STATE.ERROR
            return None
 
    parse_subscribe(renew_uuid, body)

