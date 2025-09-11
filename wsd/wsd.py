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
from scanner import Scanner


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
        logger.debug(f"{datetime.datetime.now():%Y-%m-%d %H:%M:%S} [WSD] Error while parsing: {e}")
        return None

# ---------------- XADDR filtern ----------------
def pick_best_xaddr(xaddrs: str) -> str:
    """
    Wählt aus einer Liste von XAddrs den besten Kandidaten:
    - bevorzugt IPv4
    - ignoriert IPv6, wenn IPv4 vorhanden ist
    - nimmt den Hostnamen, falls keine IP vorhanden ist
    """
    logger.info(f"{datetime.datetime.now():%Y-%m-%d %H:%M:%S} [WSD:XADDR] received {xaddrs}")
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

    logger.info(f"{datetime.datetime.now():%Y-%m-%d %H:%M:%S} [WSD:XADDR] extracted {ipv4 or hostname or None}")

    return ipv4 or hostname or None

# ---------------- UDP Discovery Skeleton ----------------
async def discovery_listener():
#    loop = asyncio.get_running_loop()

    # WSD (3702)
    MCAST_GRP = "239.255.255.250"
    MCAST_PORT = 3702
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("", MCAST_PORT))
    mreq = socket.inet_aton(MCAST_GRP) + socket.inet_aton("0.0.0.0")
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
    logger.info("WSD-Listener running on Port 3702/UDP")

    logger.info(f"-----------------------  Events  -------------------------")

    loop = asyncio.get_running_loop()
    while True:
        data, addr = await loop.sock_recvfrom(sock, 8192)
        ip = addr[0]
        
        try:
            root = ET.fromstring(data.decode("utf-8", errors="ignore"))
        except Exception:
            continue

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

        logger.info(f"{datetime.datetime.now():%Y-%m-%d %H:%M:%S} [WSD:DISCOVERY] received from {ip}")
        logger.info(f"{datetime.datetime.now():%Y-%m-%d %H:%M:%S} [WSD:DISCOVERY]    -->   UUID: {uuid}")
        logger.info(f"{datetime.datetime.now():%Y-%m-%d %H:%M:%S} [WSD:DISCOVERY]    --> Action: {action_text}")
        logger.info(f"{datetime.datetime.now():%Y-%m-%d %H:%M:%S} [WSD:DISCOVERY]    -->  Types: {types_text}")
        logger.info(f"{datetime.datetime.now():%Y-%m-%d %H:%M:%S} [WSD:DISCOVERY]    -->  XADDR: {xaddr}")

        # Nur Scanner beachten
#        if "wscn:ScanDeviceType" not in types_text:
#        if "ScanDeviceType" not in types_text:
#            continue
#        else:
#            logger.info(f"Device seems not to be a Scanner")

        if "Hello" in action_text:
#            uuid = root.find(".//{http://schemas.xmlsoap.org/ws/2004/08/addressing}Address")
#            uuid = uuid.text.strip() if uuid is not None else f"UUID-{ip}"
            if uuid not in SCANNERS:
                SCANNERS[uuid] = Scanner(name=f"Scanner-{ip}", ip=ip, uuid=uuid)
                logger.info(f"{datetime.datetime.now():%Y-%m-%d %H:%M:%S} [WSD:HELLO] New Scanner: {SCANNERS[uuid].name} ({ip})")
            else:
                SCANNERS[uuid].update()
                logger.info(f"{datetime.datetime.now():%Y-%m-%d %H:%M:%S} [WSD:HELLO]known Scanner updated/back again: {SCANNERS[uuid].name} ({ip})")

#            Scanner.list_scanners()
            list_scanners()
        
        elif "Bye" in action_text:
            #uuid = root.find(".//{http://schemas.xmlsoap.org/ws/2004/08/addressing}Address")
            #uuid = uuid.text.strip() if uuid is not None else f"UUID-{ip}"
            logger.info(f"{datetime.datetime.now():%Y-%m-%d %H:%M:%S} [WSD:BYE] Bye for uuid: {uuid}")
            list_scanners()
            if uuid in SCANNERS:
                logger.info(f"{datetime.datetime.now():%Y-%m-%d %H:%M:%S} [WSD:BYE] Scanner offline: {SCANNERS[uuid].name} ({ip})")
                del SCANNERS[uuid]
                list_scanners()
            #return
        
        else:
            logger.info(f"unrecognized operation {action_text}")
            #return
        await asyncio.sleep(0)  # kurz Yield zurück an Loop
        # Nach jedem Update: Liste loggen
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


# Offene Tasks abbrechen (sonst sammeln sie sich an)
    #    for task in pending:
    #        task.cancel()

#                    logger.info(f"{datetime.datetime.now():%Y%m%d %H%M%S} [WSD] from {addr} → Action={parsed['action']} UUID={parsed['uuid']}")
#                        logger.info(f"{datetime.datetime.now():%Y%m%d %H%M%S} [DISCOVERY] [WSD] Neuer Scanner: {s.name} ({s.ip})")
#                    logger.debug(f"{datetime.datetime.now():%Y%m%d %H%M%S} [WSD] unknown packet from {addr}: {data[:80]!r}")
#                   logger.info(f"{datetime.datetime.now():%Y%m%d %H%M%S} [SSDP] from {addr} → NT={headers.get('NT')} USN={headers.get('USN')}")
#                        logger.info(f"{datetime.datetime.now():%Y%m%d %H%M%S} [DISCOVERY] [SSDP] Neuer Scanner: {s.name} ({s.ip})")
#                    logger.debug(f"{datetime.datetime.now():%Y%m%d %H%M%S} [SSDP] unknown packet from {addr}: {data[:80]!r}")
#                            logger.info(f"[WSD] new Scanner detected: {s.name} ({s.ip}) UUID={s.uuid}")
#                    logger.warning(f"[WSD] Error while parsing: {e}")#
#                        logger.info(f"[SSDP] new Scanner detected: {s.name} ({s.ip}) UUID={s.uuid} location={location}")
#                        SCANNERS[uuid].update(max_age=max_age)
#            logger.info(f"[DISCOVERY] Neuer Scanner erkannt: {s.name} ({s.ip}) online")


# ---------------- Scanner Keepalive checken ----------------
async def check_scanner(scanner):
    try:
        await fetch_metadata(scanner)  # nutzt SOAP-Get
        scanner.update(scanner.max_age)
        logger.info(f"[Heartbeat OK] {scanner.ip} lebt noch")
    except Exception as e:
        logger.warning(f"[Heartbeat FAIL] {scanner.ip}: {e}")

# ---------------- Scanner Heartbeat ----------------
async def heartbeat_monitor():
    while True:
        now = datetime.datetime.now()
        to_remove = []
        logger.info(f"[Heartbeat] wake-up")

#        for scanner in list(scanners):
        for scanner in list(SCANNERS):
            logger.info(f"[Heartbeat] Timer-Check for {scanner.ip}...")
            age = (now - scanner.last_seen).total_seconds()
            timeout = scanner.max_age

            # Halbzeit-Check
            if age > timeout / 2 and age <= (timeout / 2 + 30):
                logger.info(f"[Heartbeat] --> proceeding Halbzeit-Check")
                asyncio.create_task(check_scanner(scanner))

            # 3/4-Check
            if age > (timeout * 0.75) and age <= (timeout * 0.75 + 30):
                logger.info(f"[Heartbeat] --> proceeding Viertel-Check")
                asyncio.create_task(check_scanner(scanner))

            # Timeout überschritten → offline markieren
            if age > timeout and scanner.online:
                logger.info(f"[Heartbeat] --> mark as offline")
                scanner.mark_offline()

            # Nach Ablauf von Timeout+Offline → entfernen
            if not scanner.online and scanner.remove_after and now >= scanner.remove_after:
                logger.info(f"[Heartbeat] --> Marking {scanner.ip} ({scanner.friendly_name or scanner.name}) to remove")
                to_remove.append(scanner)

        for s in to_remove:
            logger.info(f"[Heartbeat]     --> Removing {scanner.ip} ({scanner.friendly_name or scanner.name}) from list")
            scanners.remove(s)

        await asyncio.sleep(30)
        
#        for s in SCANNERS.values():
#            delta = (now - s.last_seen).total_seconds()
#            if delta > WSD_OFFLINE_TIMEOUT and s.online:
#                s.online = false
#                logger.warning(f"{datetime.datetime.now():%Y%m%d %H%M%S} [DISCOVERY] Scanner {s.name} ({s.ip}) offline since {WSD_OFFLINE_TIMEOUT} Seconds")
#        await asyncio.sleep(5)


# ---------------- HTTP/SOAP Server ----------------
async def handle_scan_job(request):
    logger.info(f"{datetime.datetime.now():%Y-%m-%d %H:%M:%S} [SCAN] Scan-Job started")
    data = await request.read()
    logger.info(f"{datetime.datetime.now():%Y-%m-%d %H:%M:%S} [SCAN] Received first Bytes: {len(data)}")
    #logger.debug(f"[SCAN] Received first Bytes: {len(data)}")
    filename = WSD_SCAN_FOLDER / f"scan-{datetime.datetime.now():%Y%m%d_%H%M%S}.bin"
    try:
        with open(filename, "wb") as f:
            f.write(data)
        logger.info(f"{datetime.datetime.now():%Y-%m-%d %H:%M:%S} [SCAN] Scan finished: {filename} ({len(data)/1024:.1f} KB)")
    except Exception as e:
        logger.error(f"{datetime.datetime.now():%Y-%m-%d %H:%M:%S} [SCAN] Error while saving: {e}")
    return web.Response(text="""
        <soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope">
            <soap:Body>
                <ScanJobResponse>OK</ScanJobResponse>
            </soap:Body>
        </soap:Envelope>
    """, content_type='application/soap+xml')
