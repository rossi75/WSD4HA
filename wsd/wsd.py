import os
import asyncio
#from aiohttp import web
import aiohttp
from pathlib import Path
import datetime
import socket
import logging
import sys
import re
import xml.etree.ElementTree as ET
import subprocess
#from state import SCANNERS
#from globals import SCANNERS, list_scanners, NAMESPACES
from globals import SCANNERS, list_scanners, NAMESPACES, ScannerStatus
#from globals import SCANNERS, list_scanners, OFFLINE_TIMEOUT
from scanner import Scanner
#from config import OFFLINE_TIMEOUT
#from config import OFFLINE_TIMEOUT, LOCAL_IP
from config import OFFLINE_TIMEOUT, LOCAL_IP, HTTP_PORT
#from scanner import Scanner, fetch_metadata
import uuid
from templates import SOAP_PROBE_TEMPLATE
#import aiohttp
#from datetime import datetime, timedelta
#from utils import pick_best_xaddr  # deine vorhandene Hilfsfunktion

logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')
logger = logging.getLogger("wsd-addon")

import time
import threading

# ---------------- WSD SOAP Parser ----------------
def parse_wsd_packet(data: bytes):
    try:
        xml = ET.fromstring(data.decode("utf-8", errors="ignore"))
        action = xml.find(".//{http://schemas.xmlsoap.org/ws/2004/08/addressing}Action")
        uuid = xml.find(".//{http://schemas.xmlsoap.org/ws/2004/08/addressing}Address")
        return {
            "action": action.text if action is not None else None,
            "uuid": uuid.text if uuid is not None else None,
        }
    except Exception as e:
        logger.debug(f"[WSD] Error while parsing: {e}")
        return None

# ---------------- XADDR filtern ----------------
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


# ---------------- Message handler ----------------
async def discovery_processor(data, addr):
    logger.info(f"{datetime.datetime.now():%Y-%m-%d %H:%M:%S} [Message] Processing sth")
    logger.debug(f" [Message]    ---> received data {data}")
    logger.debug(f" [Message]    ---> received addr {addr}")
    ip = addr[0] if addr else "?"

    try:
        root = ET.fromstring(data.decode("utf-8", errors="ignore"))
    except Exception:
        logger.warning("[WSD:hm] Exception while reading from ET")
        return

    # UUID (without urn:uuid:)
    uuid_raw = root.find(".//wsa:Address", NAMESPACES)
    uuid = None
    if uuid_raw is not None and uuid_raw.text:
        uuid_text = uuid_raw.text.strip()
        if uuid_text.startswith("urn:uuid:"):
            uuid = uuid_text.replace("urn:uuid:", "")
        else:
            uuid = uuid_text

    # extract Action
    action_elem = root.find(".//wsa:Action", NAMESPACES)
    action_text = None
    if action_elem is not None and action_elem.text:
        action_text = action_elem.text.split("/")[-1]  # → "Hello|Bye|Probe"

    # extract Device Capability        
    types_elem = root.find(".//wsd:Types", NAMESPACES)
    types_text = ""
    if types_elem is not None and types_elem.text:
        # Zerlegen + Präfixe entfernen
        types_text = " ".join(t.split(":")[-1] for t in types_elem.text.split())

    # exctract XAddrs
    xaddrs_elem = root.find(".//{http://schemas.xmlsoap.org/ws/2005/04/discovery}XAddrs")
    xaddr = ""
    if xaddrs_elem is not None and xaddrs_elem.text:
        xaddr = pick_best_xaddr(xaddrs_elem.text.strip()) + "/scan"

    logger.info(f"[WSD:DISCOVERY] received from {ip}")
    logger.info(f"    -->   UUID: {uuid}")
    logger.info(f"    --> Action: {action_text}")
    logger.info(f"    -->  Types: {types_text}")
    logger.info(f"    -->  XADDR: {xaddr}")

    if action_text == "Hello":
        # Nur Scanner berücksichtigen
        if "ScanDeviceType" not in types_text:
            logger.info(f"[WSD:HELLO] Ignored non-scanner device UUID={uuid} Types={types_text}")
            return

        if uuid not in SCANNERS:
            SCANNERS[uuid] = Scanner(uuid=uuid, ip=ip, xaddr=xaddr)
            logger.info(f"[WSD:HELLO] New Scanner: {SCANNERS[uuid].uuid} ({ip})")
        else:
            if SCANNERS[uuid].state.value == "online":
                SCANNERS[uuid].update()
            logger.info(f"[WSD:HELLO] known Scanner seen again: {SCANNERS[uuid].friendly_name} ({ip})")

            # ===>> wird nun vom probe_monitor() erledigt
#            res = await subscribe_to_scanner(SCANNERS[uuid], my_notify_url=f"http://{LOCAL_IP}:{HTTP_PORT}/wsd/notify")
#            if res["ok"]:
#                logger.info("   ---> subscribed id=%s expires=%s", res["identifier"], res["expires"])
#            else:
#                logger.warning("   ---> subscribe failed: %s", res.get("reason"))

        list_scanners()

    elif action_text == "Bye":
        logger.info(f"[WSD:BYE] Bye for uuid: {uuid}")
        if uuid in SCANNERS:
            logger.info(f"[WSD:BYE] Scanner offline: {SCANNERS[uuid].friendly_name} ({ip})")
            del SCANNERS[uuid]
        list_scanners()

    else:
        logger.warning(f"[WSD:Message] received unrecognized operation {action_text} from {ip}")

    logger.info(f"[WSD:Message] done")


# ---------------- UDP listener ----------------
async def UDP_listener_3702():
    # WSD (Port 3702/UDP)
    MCAST_GRP = "239.255.255.250"
    MCAST_PORT = 3702

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("", MCAST_PORT))
    mreq = socket.inet_aton(MCAST_GRP) + socket.inet_aton("0.0.0.0")
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
    sock.setblocking(False)   # WICHTIG für asyncio!
    logger.info("WSD-Listener running on Port 3702/UDP")
    logger.info(f"-----------------------  Events  -------------------------")

    # Daten abholen
    loop = asyncio.get_running_loop()
    async def recv_loop():
        while True:
            logger.debug(f"{datetime.datetime.now():%Y-%m-%d %H:%M:%S} [WSD:recv_loop] waiting for UDP data")
            data, addr = await loop.sock_recvfrom(sock, 8192)
            await discovery_processor(data, addr)   # ausgelagerte Verarbeitung
            await asyncio.sleep(1)

    # asyncio.create_task(recv_loop())
    await recv_loop()

# ---------------- Scanner Probe ----------------
async def state_monitor():
    while True:
        logger.debug(f"{datetime.datetime.now():%Y-%m-%d %H:%M:%S} [WSD:Probe] wake-up")
        to_remove = []
        now = datetime.datetime.now()

        for uuid, scanner in SCANNERS.items():
            logger.info(f"{datetime.datetime.now():%Y-%m-%d %H:%M:%S} [WSD:Probe] Timer-Check for {uuid} ({scanner.ip})...")
            status = scanner.state.value
            age = (now - scanner.last_seen).total_seconds()
            logger.info(f"   -->    status: {status}")
            logger.info(f"   --> last_seen: {scanner.last_seen}")
            logger.info(f"   -->       age: {age}")
#            logger.debug(f"   -->       age = {age}")

            if status in ("discovered"):
                logger.info(f"[WSD:probe_mon] Fresh discovered, now probing...")
                try:
                    logger.info(f"[WSD:probe_mon]   LogPoint B")
                    asyncio.create_task(send_probe(scanner))
                    logger.info(f"[WSD:probe_mon]   LogPoint C")
                except Exception as e:
                    scanner.state = ScannerStatus.ERROR
                    logger.warning(f"Anything went wrong while probing the UUID {uuid} @ {ip}, response is {str(e)}")

            if status in ("parsing_probe"):
                logger.info(f"[WSD:probe_mon] probe done, parsing probe...")
                try:
                    logger.info(f"[WSD:probe_mon]   LogPoint E")
                    asyncio.create_task(parse_probe(scanner))
                    logger.info(f"[WSD:probe_mon]   LogPoint F")
                except Exception as e:
                    scanner.state = ScannerStatus.ERROR
                    logger.warning(f"Anything went wrong while parsing the Probe from UUID {uuid} @ {ip}, response is {str(e)}")

            if status in ("online"):
                # Halbzeit-Check
                if age > OFFLINE_TIMEOUT / 2 and age <= (OFFLINE_TIMEOUT / 2 + 30):
                    logger.info(f"[WSD:Probe] --> proceeding Halbzeit-Check")
                    try:
                        asyncio.create_task(send_probe(uuid))
                        scanner.update()
                    except Exception as e:
                        scanner.state = ScannerStatus.ABSENT
                        logger.warning(f"{datetime.datetime.now():%Y-%m-%d %H:%M:%S} Could not reach scanner with UUID {uuid} and IP {ip}. Last seen at {scanner.last_seen}. Response is {str(e)}")
    
                # 3/4-Check
                if age > (OFFLINE_TIMEOUT * 0.75) and age <= (OFFLINE_TIMEOUT * 0.75 + 30):
                    logger.info(f"[WSD:Heartbeat] --> proceeding Viertel-Check")
                    try:
                        asyncio.create_task(send_probe(uuid))
                        scanner.update()
                    except Exception as e:
                        logger.warning(f"{datetime.datetime.now():%Y-%m-%d %H:%M:%S} Could not reach scanner with UUID {uuid} and IP {ip}. Last seen at {scanner.last_seen}. Response is {str(e)}")
    
            # Timeout überschritten → offline markieren, damit werden alle Zwischenstati erschlagen, für den Fall dass was hängen geblieben ist und auch für ERROR
            if age > OFFLINE_TIMEOUT:
                logger.info(f"[WSD:Heartbeat] --> mark as offline")
                scanner.mark_absent()

            # Nach Ablauf von Timeout+Offline → entfernen
            if status in ("absent") and now >= scanner.remove_after:
                logger.info(f"[WSD:Heartbeat] --> Marking {scanner.ip} ({scanner.friendly_name}) to remove")
                to_remove.append(scanner)

            logger.info(f"   -->    status: {status}")
#            logger.debug(f"   -->    status = {status}")
    
        # welche Scanner sollen entfernt werden?
        logger.debug(f"[WSD:Heartbeat] checking for Scanners to remove from known list")
        for s in to_remove:
            logger.warning(f"[Heartbeat]     --> Removing {scanner.ip} ({scanner.friendly_name}) from list")
            del SCANNERS[scanner.uuid]
            list_scanners()
          
        logger.debug(f"{datetime.datetime.now():%Y-%m-%d %H:%M:%S} [WSD:Probe] goodbye")
        #await asyncio.sleep(30)
        await asyncio.sleep(OFFLINE_TIMEOUT / 4)
        logger.debug(f"{datetime.datetime.now():%Y-%m-%d %H:%M:%S} [WSD:Probe] back in town")

# ---------------- Send Scanner Probe ----------------
async def send_probe(scanner):
    logger.info(f"{datetime.datetime.now():%Y-%m-%d %H:%M:%S} [WSD:send_probe] sending probe for {scanner.uuid} @ {scanner.ip}")
    scanner.status = ScannerStatus.PROBING
    msg_id = uuid.uuid4()
    xml = SOAP_PROBE_TEMPLATE.format(msg_id=msg_id)

    headers = {
        "Content-Type": "application/soap+xml",
        #"User-Agent": "WSD4HA",
        "User-Agent": "WSDAPI",
    }

#    for xaddr in scanner.xaddr:
    url = f"http://{scanner.ip}:80/StableWSDiscoveryEndpoint/schemas-xmlsoap-org_ws_2005_04_discovery"

    logger.info(f"   ---> URL: {url}")
    logger.info(f"   ---> XML:")
    logger.info({xml})
    
    async with aiohttp.ClientSession() as session:
        try:
            async with session.post(url, data=xml, headers=headers, timeout=5) as resp:
                if resp.status == 200:
                    body = await resp.text()
#                    logger.debug(f"ProbeMatch von {scanner.ip}:\n{body}")
                    logger.info(f"ProbeMatch von {scanner.ip}:\n{body}")
        except Exception as e:
            scanner.status = ScannerStatus.ABSENT
            logger.info(f"   ---> Probe fehlgeschlagen bei {url}: {e}")

#    logger.debug(f"   ---> Statuscode: {resp.status}")
    logger.info(f"   ---> Statuscode: {resp.status}")

    return {body}

# ---------------- Probe Parser ----------------
def parse_probe(xml: str, scanners: dict):
    """
    Parse ProbeMatch response and update/create Scanner objects.

    Args:
        xml (str): SOAP XML response as string
        scanners (dict): Dictionary {uuid: Scanner}

    Returns:
        dict: updated scanners
    """
    logger.info(f"{datetime.datetime.now():%Y-%m-%d %H:%M:%S} [WSD:parse_probe] parsing probe from {scanner.uuid} @ {scanner.ip}")
    scanner.status = ScannerStatus.PROBE_PARSING
    affected = []

    try:
        root = ET.fromstring(xml)
    except ET.ParseError as e:
        logger.error(f"[WSD:probe_parser] XML ParseError: {e}")
        scanner.status = ScannerStatus.ERROR
        return scanners

    for pm in root.findall(".//wsd:ProbeMatch", NAMESPACE):
        uuid_elem = pm.find(".//wsa:Address", NAMESPACE)
        types_elem = pm.find(".//wsd:Types", NAMESPACE)
        xaddrs_elem = pm.find(".//wsd:XAddrs", NAMESPACE)

        if uuid_elem is None or types_elem is None or xaddrs_elem is None:
            logger.warning("[WSD:probe_parser] Incomplete ProbeMatch, skipping")
            scanner.status = ScannerStatus.ERROR
            continue

        uuid = uuid_elem.text.strip()
        types = types_elem.text.strip().split()
        xaddr = pick_best_xaddr(xaddrs_elem.text.strip())

        # Nur Scanner akzeptieren
        if not any("ScanDeviceType" in t for t in types):
            logger.info(f"[WSD:probe_parser] Skipping non-scanner device {uuid}")
            scanner.status = ScannerStatus.ERROR
            continue

        # neuer oder vorhandener Scanner?
        if uuid not in scanners:
#            scanners[uuid] = Scanner(uuid=uuid, ip=xaddr, xaddr=[xaddr])
#            scanners[uuid] = Scanner(uuid=uuid, ip=xaddr, xaddr=xaddr)
#            scanners[uuid].related_uuids = set()
#            scanners[uuid].status = ScannerStatus.PROBE_PARSED
            scanners[uuid] = Scanner(uuid=uuid, ip=xaddr, xaddr=xaddr)
            scanners[uuid].related_uuids = set()
            scanners[uuid].status = ScannerStatus.PROBE_PARSED
            logger.info(f"[WSD:probe_parser] New scanner discovered: {uuid} @ {xaddr}")
        else:
#            scanner = scanners[uuid]
#            scanner.xaddr = [xaddr]
            scanners[uuid].xaddr = xaddr
            scanner.status = ScannerStatus.PROBE_PARSED
            logger.info(f"[WSD:probe_parser] Updated scanner {uuid} -> {xaddr}")

    return scanners
