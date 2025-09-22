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
from config import OFFLINE_TIMEOUT, LOCAL_IP, HTTP_PORT, FROM_UUID
from globals import SCANNERS, list_scanners, NAMESPACES, STATE
from pathlib import Path
from scanner import Scanner
from templates import TEMPLATE_SOAP_PROBE, TEMPLATE_SOAP_TRANSFER_GET
from parse import parse_wsd_packet, parse_probe, parse_transfer_get

# ---------------- Send Scanner Probe ----------------
async def send_probe(scanner):
    logger.info(f"{datetime.datetime.now():%Y-%m-%d %H:%M:%S} [WSD:send_probe] sending probe for {scanner.uuid} @ {scanner.ip}")

    scanner.state = STATE.PROBING
    msg_id = uuid.uuid4()
    xml = TEMPLATE_SOAP_PROBE.format(msg_id=msg_id)

    headers = {
        "Content-Type": "application/soap+xml",
        #"User-Agent": "WSD4HA",
        "User-Agent": "WSDAPI",
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
                    logger.warning(f"Probe failed with status {resp.status}")
                    scanner.state = STATE.ABSENT
        except Exception as e:
            logger.info(f"   ---> Probe fehlgeschlagen bei {url}: {e}")
            scanner.state = STATE.ABSENT

    logger.info(f"ProbeMatch von {scanner.ip}:\n{body}")
    parse_probe(body, scanner.uuid)

#    logger.debug(f"   ---> Statuscode: {resp.status}")
    logger.info(f"   ---> Statuscode: {resp.status}")


# ---------------- Send Transfer_Get ----------------
async def send_transfer_get(tf_g_uuid: str):
    logger.info(f"{datetime.datetime.now():%Y-%m-%d %H:%M:%S} [WSD:transfer_get] sending Transfer/Get to {tf_g_uuid} @ {SCANNERS[tf_g_uuid].ip}")
    
    SCANNERS[tf_g_uuid].state = STATE.TF_GET_PENDING
    msg_id = uuid.uuid4()

    xml = TEMPLATE_SOAP_TRANSFER_GET.format(
        to_device_uuid=tf_g_uuid,
        msg_id=msg_id,
        from_uuid=FROM_UUID
    )

    headers = {
        "Content-Type": "application/soap+xml",
        "User-Agent": "WSDAPI",
    }

    url = SCANNERS[tf_g_uuid].xaddr  # z.B. http://192.168.0.3:8018/wsd

    logger.info(f"   --->    FROM: {FROM_UUID}")
    logger.info(f"   --->      TO: {tf_g_uuid}")
    logger.info(f"   --->  MSG_ID: {msg_id}")
    logger.info(f"   --->     URL: {url}")
    logger.info(f"   --->     XML:\n{xml}")

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

