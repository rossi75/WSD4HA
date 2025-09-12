import os
import asyncio
from aiohttp import web
from pathlib import Path
import datetime
import socket
import logging
import sys
import re
import xml.etree.ElementTree as ET
import subprocess
#from state import SCANNERS
from globals import SCANNERS, list_scanners 
#from globals import SCANNERS, list_scanners, OFFLINE_TIMEOUT
from scanner import Scanner
from config import OFFLINE_TIMEOUT
#from scanner import Scanner, fetch_metadata


NAMESPACES = {
    "soap": "http://www.w3.org/2003/05/soap-envelope",
    "wsd": "http://schemas.xmlsoap.org/ws/2005/04/discovery",
    "wsa": "http://schemas.xmlsoap.org/ws/2004/08/addressing"
}

logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')
logger = logging.getLogger("wsd-addon")

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
#        logger.debug(f"{datetime.datetime.now():%Y-%m-%d %H:%M:%S} [WSD] Error while parsing: {e}")
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
    logger.info(f"{datetime.datetime.now():%Y-%m-%d %H:%M:%S}[WSD:XADDR] received {xaddrs}")
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

#    logger.info(f"{datetime.datetime.now():%Y-%m-%d %H:%M:%S}[WSD:XADDR] extracted {ipv4 or hostname or None}")
    logger.info(f"[WSD:XADDR] extracted {ipv4 or hostname or None}")

    return ipv4 or hostname or None


# ---------------- Message handler ----------------
async def message_processor(data, addr):
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
        xaddr = pick_best_xaddr(xaddrs_elem.text.strip())

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
            #continue

        if uuid not in SCANNERS:
#            SCANNERS[uuid] = Scanner(name=f"IP_{ip}", ip=ip, uuid=uuid)
            SCANNERS[uuid] = Scanner(uuid=uuid, ip=ip, xaddr=xaddr)
            logger.info(f"[WSD:HELLO] New Scanner: {SCANNERS[uuid].uuid} ({ip})")
        else:
            logger.info(f"[WSD:MESSAGE_DEBUG] BEFORE update: {self.uuid}, xaddr={self.xaddr}")
            SCANNERS[uuid].update()
            logger.info(f"[WSD:HELLO] known Scanner updated/back again: {SCANNERS[uuid].friendly_name} ({ip})")
#            logger.info(f"[WSD:HELLO] known Scanner updated/back again: {SCANNERS[uuid].name} ({ip})")
            logger.info(f"[WSD:MESSAGE_DEBUG] AFTER update: {self.uuid}, xaddr={self.xaddr}")

        list_scanners()

    elif action_text == "Bye":
        logger.info(f"[WSD:BYE] Bye for uuid: {uuid}")
        if uuid in SCANNERS:
            logger.info(f"[WSD:BYE] Scanner offline: {SCANNERS[uuid].friendly_name} ({ip})")
            del SCANNERS[uuid]
        list_scanners()

    else:
        logger.warning(f"[WSD:Message] unrecognized operation {action_text}")

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
#            logger.info(f"{datetime.datetime.now():%Y-%m-%d %H:%M:%S}[WSD:recv_loop] 1")
            logger.debug(f"{datetime.datetime.now():%Y-%m-%d %H:%M:%S}[WSD:recv_loop] waiting for UDP data")
            data, addr = await loop.sock_recvfrom(sock, 8192)
#            logger.info(f"{datetime.datetime.now():%Y-%m-%d %H:%M:%S}[WSD:recv_loop] 2")
            await message_processor(data, addr)   # ausgelagerte Verarbeitung
#            logger.info(f"{datetime.datetime.now():%Y-%m-%d %H:%M:%S}[WSD:recv_loop] 3")
            await asyncio.sleep(1)
#            logger.info(f"{datetime.datetime.now():%Y-%m-%d %H:%M:%S}[WSD:recv_loop] 4")

    # asyncio.create_task(recv_loop())
    await recv_loop()

    # Hier nur Task starten!
#    asyncio.create_task(handle_messages())# Nach jedem Update: Liste loggen
#        logger.info("[SCANNERS] registered Scanners:")
#        for s in SCANNERS.values():
#            logger.info(f"  - {s.name} ({s.ip}, {s.uuid})")
#        for idx, s in enumerate(SCANNERS.values(), start=1):
#            logger.info(f"[{idx}] {s.name} ({s.ip}) UUID={s.uuid} Online={s.online}")

#        logger.info(f"[WSD:p1] {uuid}")
        # erst das objekt neu erstellen
#        scanner = Scanner(name=uuid, ip=addr[0], uuid=uuid, xaddr=xaddr)
#        logger.info(f"[WSD:p1]")
#        scanners.append(scanner)
        # dann das Objekt der Liste hinzufügen
#        SCANNERS[uuid] = scanner

        # sofort Metadata laden
#        asyncio.create_task(fetch_metadata(scanner))
#        asyncio.create_task(Scanner.fetch_metadata())
#        asyncio.create_task(Scanner.fetch_metadata(SCANNERS[uuid]))
#        asyncio.create_task(Scanner.fetch_metadata(scanner))
#        asyncio.create_task(Scanner.fetch_metadata(Scanner))
#        await scanner.fetch_metadata(uuid)
#        await SCANNERS[uuid].fetch_metadata()
 
#        logger.info(f"[WSD:p2]")
#        try:
#            logger.info(f"[WSD:p3]")
#            asyncio.create_task(Scanner.fetch_metadata(Scanner))
    #        await fetch_metadata(scanner)  # nutzt SOAP-Get
#            logger.info(f"[WSD_fmd]")
#        except Exception as e:
#            logger.warning(f"[Heartbeat FAIL] {Scanner.ip}: {e}")
#            logger.warning(f"[Heartbeat FAIL] {scanner.ip}: {e}")
#        logger.info(f"[WSD:p4]")



# ---------------- Scanner Keepalive checken ----------------
async def check_scanner(scanner):
    try:
#        await fetch_metadata(scanner)  # nutzt SOAP-Get
        logger.info(f"[WSD:CHECK_SCANNER_DEBUG] BEFORE update: {scanner.uuid}, xaddr={scanner.xaddr}")
        await scanner.fetch_metadata()  # nutzt SOAP-Get
#        scanner.update(scanner.max_age)
        logger.info(f"[WSD:CHECK_SCANNER_DEBUG] AFTER update: {scanner.uuid}, xaddr={scanner.xaddr}")
        scanner.update(OFFLINE_TIMEOUT)
        logger.info(f"[WSD:Heartbeat OK] {scanner.friendly_name or scanner.ip} lebt noch")
    except Exception as e:
        logger.warning(f"[WSD:Heartbeat FAIL] {scanner.friendly_name or scanner.ip}: {e}")

# ---------------- Scanner Heartbeat ----------------
async def heartbeat_monitor():
    while True:
        now = datetime.datetime.now()
        to_remove = []
        logger.info(f"{datetime.datetime.now():%Y-%m-%d %H:%M:%S}[WSD:Heartbeat] wake-up")

        for uuid, scanner in SCANNERS.items():
            logger.info(f"[WSD:Heartbeat] Timer-Check for {uuid} ({scanner.ip})...")
            age = (now - scanner.last_seen).total_seconds()
#            timeout = scanner.max_age
            logger.info(f"   --> last_seen = {scanner.last_seen}")
            logger.info(f"   -->       age = {age}")
#            logger.info(f"   -->   timeout = {timeout}")
            logger.info(f"   -->      uuid = {uuid}")
#            logger.info(f"   -->     xaddr = {xaddr}")
            logger.info(f"   -->     xaddr = {scanner.xaddr}")

            # Halbzeit-Check
            if age > timeout / 2 and age <= (timeout / 2 + 30):
                logger.info(f"[WSD:Heartbeat] --> proceeding Halbzeit-Check")
                asyncio.create_task(check_scanner(scanner))

            # 3/4-Check
            if age > (timeout * 0.75) and age <= (timeout * 0.75 + 30):
                logger.info(f"[WSD:Heartbeat] --> proceeding Viertel-Check")
                asyncio.create_task(check_scanner(scanner))

            # Timeout überschritten → offline markieren
            if age > timeout and scanner.online:
                logger.info(f"[WSD:Heartbeat] --> mark as offline")
                scanner.mark_offline()

            # Nach Ablauf von Timeout+Offline → entfernen
            if not scanner.online and scanner.remove_after and now >= scanner.remove_after:
                logger.info(f"[WSD:Heartbeat] --> Marking {scanner.ip} ({scanner.friendly_name}) to remove")
                to_remove.append(scanner)

        # welche Scanner sollen entfernt werden?
        logger.debug(f"[WSD:Heartbeat] checking for Scanners to remove from known list")
        for s in to_remove:
            logger.info(f"[Heartbeat]     --> Removing {scanner.ip} ({scanner.friendly_name}) from list")
#            scanners.remove(s)
            scanner.remove(s)

        logger.debug(f"{datetime.datetime.now():%Y-%m-%d %H:%M:%S}[WSD:Heartbeat] goodbye")
        #await asyncio.sleep(30)
        await asyncio.sleep(10)
        logger.debug(f"{datetime.datetime.now():%Y-%m-%d %H:%M:%S}[WSD:Heartbeat] back in town")



