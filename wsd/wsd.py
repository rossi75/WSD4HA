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
#from globals import SCANNERS, list_scanners, NAMESPACES, STATE, FROM_UUID
from globals import SCANNERS, list_scanners, NAMESPACES, STATE
from pathlib import Path
from scanner import Scanner
from templates import TEMPLATE_SOAP_PROBE, TEMPLATE_SOAP_TRANSFER_GET
from send import send_probe, send_transfer_get
from parse import parse_wsd_packet, parse_probe, parse_transfer_get

logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')
logger = logging.getLogger("wsd-addon")

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
    logger.info(f"{datetime.datetime.now():%Y-%m-%d %H:%M:%S} [WSD:Disc_Proc] Processing something from {addr[0]}")
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
#    xaddrs_elem = root.find(".//{http://schemas.xmlsoap.org/ws/2005/04/discovery}XAddrs")
    xaddrs_elem = root.find(".//wsd:XAddrs", NAMESPACES)
    xaddr = ""
    if xaddrs_elem is not None and xaddrs_elem.text:
#        xaddr = pick_best_xaddr(xaddrs_elem.text.strip()) + "/scan"
        xaddr = pick_best_xaddr(xaddrs_elem.text.strip())

    logger.debug(f"    -->   UUID: {uuid}")
    logger.info(f"    --> Action: {action_text}")
    logger.debug(f"    -->  Types: {types_text}")
    logger.debug(f"    -->  XADDR: {xaddr}")

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

        list_scanners()

    elif action_text == "Bye":
        logger.info(f"[WSD:BYE] Bye for uuid: {uuid}")
        if uuid in SCANNERS:
            logger.warning(f"[WSD:BYE] Scanner offline: {SCANNERS[uuid].friendly_name} ({ip})")
            del SCANNERS[uuid]
        list_scanners()

    else:
        logger.warning(f"[WSD:Message] received unrecognized operation {action_text} from {ip}")

    logger.debug(f"[WSD:Message] done")


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
        now = datetime.datetime.now().replace(microsecond=0)

        for uuid, scanner in SCANNERS.items():
            logger.info(f"{datetime.datetime.now():%Y-%m-%d %H:%M:%S} [WSD:Probe] Checking Timer and State for {uuid} ({scanner.ip})...")
            status = scanner.state.value
            age = (now - scanner.last_seen).total_seconds()
            logger.info(f"   -->    status: {status}")
            logger.info(f"   --> last_seen: {scanner.last_seen}")
            logger.info(f"   -->       age: {age}")

            if scanner.state in STATE.PROBE_PARSED:
                logger.info(f"[WSD:probe_mon] probe parsed, get endpoint details...")
                try:
                    asyncio.create_task(send_transfer_get(uuid))
                except Exception as e:
                    scanner.state = STATE.ERROR
                    logger.warning(f"Anything went wrong while parsing the XML-Probe from UUID {uuid} @ {ip}, response is {str(e)}")

            if scanner.state in STATE.DISCOVERED:
                logger.info(f"[WSD:probe_mon] Fresh discovered, now probing...")
                try:
                    logger.info(f"[WSD:probe_mon]   LogPoint B")
                    asyncio.create_task(send_probe(scanner))
                    logger.info(f"[WSD:probe_mon]   LogPoint C")
                except Exception as e:
                    scanner.state = STATE.ERROR
                    logger.warning(f"Anything went wrong while probing the UUID {uuid} @ {ip}, response is {str(e)}")

            if scanner.state in STATE.ONLINE:
                # Halbzeit-Check
                if age > OFFLINE_TIMEOUT / 2 and age <= (OFFLINE_TIMEOUT / 2 + 30):
#                if age > OFFLINE_TIMEOUT / 2 and age <= (OFFLINE_TIMEOUT ):
                    logger.info(f"[WSD:Probe] --> proceeding Halbzeit-Check")
                    try:
                        asyncio.create_task(send_probe(uuid))
                        scanner.update()
                    except Exception as e:
                        scanner.state = STATE.ABSENT
                        logger.warning(f"{datetime.datetime.now():%Y-%m-%d %H:%M:%S} Could not reach scanner with UUID {uuid} and IP {ip}. Last seen at {scanner.last_seen}. Response is {str(e)}")
    
                # 3/4-Check
                if age > (OFFLINE_TIMEOUT * 0.75) and age <= (OFFLINE_TIMEOUT * 0.75 + 30):
#                if age > (OFFLINE_TIMEOUT * 0.75) and age <= (OFFLINE_TIMEOUT * 0.75):
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

            logger.info(f"   =====> status: {SCANNERS[uuid].state.value}")
    
        # welche Scanner sollen entfernt werden?
        logger.debug(f"[WSD:Heartbeat] checking for Scanners to remove from known list")
        for s in to_remove:
            logger.warning(f"[Heartbeat]     --> Removing {scanner.ip} ({scanner.friendly_name}) from list")
            del SCANNERS[scanner.uuid]
            list_scanners()
          
        logger.debug(f"{datetime.datetime.now():%Y-%m-%d %H:%M:%S} [WSD:sleep] goodbye")
        if any (scanner.state not in {STATE.ABSENT,
                                      STATE.ONLINE,
                                      STATE.RECV_SCAN,
                                      STATE.TO_REMOVE,
                                      STATE.ERROR}
                for scanner in SCANNERS.values()):
            logger.debug(f"{datetime.datetime.now():%Y-%m-%d %H:%M:%S} [WSD:sleep] short nap")
            await asyncio.sleep(2)
        else:
            await asyncio.sleep(OFFLINE_TIMEOUT / 4)
        logger.debug(f"{datetime.datetime.now():%Y-%m-%d %H:%M:%S} [WSD:sleep] back in town")


# ---------------- marry two endpoints ----------------
#def link_endpoints(scanner_a, scanner_b):
def marry_endpoints(uuid_a: str, uuid_b: str):
    """
    Stellt sicher, dass zwei Scanner-Objekte sich gegenseitig kennen.
    """
#    scanner_a.add_related_uuid(scanner_b.uuid)
#    scanner_b.add_related_uuid(scanner_a.uuid)
    SCANNERS[uuid_a].related_uuids += uuid_b
    SCANNERS[uuid_b].related_uuids += uuid_a
