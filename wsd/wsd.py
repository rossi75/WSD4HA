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
from config import OFFLINE_TIMEOUT, LOCAL_IP, HTTP_PORT
from globals import SCANNERS, list_scanners, NAMESPACES, STATE, FROM_UUID
from pathlib import Path
from scanner import Scanner
from templates import TEMPLATE_SOAP_PROBE, TEMPLATE_SOAP_TRANSFER_GET


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
        now = datetime.datetime.now()

        for uuid, scanner in SCANNERS.items():
            logger.info(f"{datetime.datetime.now():%Y-%m-%d %H:%M:%S} [WSD:Probe] Checking Timer and State for {uuid} ({scanner.ip})...")
            status = scanner.state.value
            age = (now - scanner.last_seen).total_seconds()
            logger.info(f"   -->    status: {status}")
            logger.info(f"   --> last_seen: {scanner.last_seen}")
            logger.info(f"   -->       age: {age}")

#            if status in ("parsing_probe"):
#                logger.info(f"[WSD:probe_mon] probe done, parsing probe...")
#                try:
#                    logger.info(f"[WSD:probe_mon]   LogPoint E")
#                    asyncio.create_task(parse_probe(body))
#                    logger.info(f"[WSD:probe_mon]   LogPoint F")
#                except Exception as e:
#                    scanner.state = STATE.ERROR
#                    logger.warning(f"Anything went wrong while parsing the XML-Probe from UUID {uuid} @ {ip}, response is {str(e)}")

            if status in ("probe_parsed"):
                logger.info(f"[WSD:probe_mon] probe parsed, get endpoint details...")
                try:
                    logger.info(f"[WSD:probe_mon]   LogPoint E")
                    #asyncio.create_task(send_transfer_get(scanner))
                    asyncio.create_task(send_transfer_get(uuid))
                    logger.info(f"[WSD:probe_mon]   LogPoint F")
                except Exception as e:
                    scanner.state = STATE.ERROR
                    logger.warning(f"Anything went wrong while parsing the XML-Probe from UUID {uuid} @ {ip}, response is {str(e)}")

            if status in ("discovered"):
                logger.info(f"[WSD:probe_mon] Fresh discovered, now probing...")
                try:
                    logger.info(f"[WSD:probe_mon]   LogPoint B")
                    asyncio.create_task(send_probe(scanner))
                    logger.info(f"[WSD:probe_mon]   LogPoint C")
                except Exception as e:
                    scanner.state = STATE.ERROR
                    logger.warning(f"Anything went wrong while probing the UUID {uuid} @ {ip}, response is {str(e)}")

            if status in ("online"):
                # Halbzeit-Check
                if age > OFFLINE_TIMEOUT / 2 and age <= (OFFLINE_TIMEOUT / 2 + 30):
                    logger.info(f"[WSD:Probe] --> proceeding Halbzeit-Check")
                    try:
                        asyncio.create_task(send_probe(uuid))
                        scanner.update()
                    except Exception as e:
                        scanner.state = STATE.ABSENT
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

            logger.info(f"   -->    status: {SCANNERS[uuid].state.value}")
#            logger.debug(f"   -->    status = {status}")
    
        # welche Scanner sollen entfernt werden?
        logger.debug(f"[WSD:Heartbeat] checking for Scanners to remove from known list")
        for s in to_remove:
            logger.warning(f"[Heartbeat]     --> Removing {scanner.ip} ({scanner.friendly_name}) from list")
            del SCANNERS[scanner.uuid]
            list_scanners()
          
        logger.debug(f"{datetime.datetime.now():%Y-%m-%d %H:%M:%S} [WSD:sleep] goodbye")
        if any (scanner.state not in {STATE.ABSENT,
                                      STATE.ONLINE,
                                      STATE.TO_REMOVE,
                                      STATE.ERROR}
                for scanner in SCANNERS.values()):
            logger.debug(f"{datetime.datetime.now():%Y-%m-%d %H:%M:%S} [WSD:sleep] short nap")
            await asyncio.sleep(2)
        else:
            await asyncio.sleep(OFFLINE_TIMEOUT / 4)
        logger.debug(f"{datetime.datetime.now():%Y-%m-%d %H:%M:%S} [WSD:sleep] back in town")

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
#                    logger.debug(f"ProbeMatch von {scanner.ip}:\n{body}")
#                    parse_probe(body, scanner.uuid)
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
#async def send_transfer_get(scanner):
async def send_transfer_get(tf_g_uuid: str):
    logger.info(f"{datetime.datetime.now():%Y-%m-%d %H:%M:%S} [WSD:transfer_get] sending Transfer/Get to {tf_g_uuid} @ {SCANNERS[tf_g_uuid].ip}")
    
    SCANNERS[tf_g_uuid].state = STATE.GET_PENDING
    #msg_id = uuid.uuid4()
    msg_id = f"urn:uuid:{uuid.uuid4()}",
    xml = TEMPLATE_SOAP_TRANSFER_GET.format(
        to_device_uuid=tf_g_uuid,
        msg_id=msg_id,
        from_uuid=FROM_UUID
    )

    headers = {
        "Content-Type": "application/soap+xml",
        "User-Agent": "WSDAPI",
    }

#    url = scanner.xaddr  # z.B. http://192.168.0.3:8018/wsd
    url = SCANNERS[tf_g_uuid].xaddr  # z.B. http://192.168.0.3:8018/wsd

    logger.info(f"   ---> FROM: {from_uuid}")
    logger.info(f"   --->   TO: {tf_g_uuid}")
    logger.info(f"   --->  MSG: {msg}")
    logger.info(f"   --->  URL: {url}")
    logger.info(f"   --->  XML:\n{xml}")

    body = ""

    async with aiohttp.ClientSession() as session:
        try:
            async with session.post(url, data=xml, headers=headers, timeout=5) as resp:
                if resp.status == 200:
                    body = await resp.text()
#                    parse_transfer_get(scanner, body)
                else:
                    SCANNERS[tf_g_uuid].state = STATE.ERROR
                    logger.error(f"[WSD:transfer_get] TransferGet failed with Statuscode {resp.status}")
                    return None
        except Exception as e:
            logger.error(f"[WSD:transfer_get] failed for {SCANNERS[tf_g_uuid].uuid}: {e}")
            SCANNERS[tf_g_uuid].state = STATE.ERROR
            return None
 
    logger.info(f"TransferGet von {SCANNERS[tf_g_uuid].ip}:\n{body}")
#    parse_transfer_get(scanner, body)
    parse_transfer_get(body, tf_g_uuid)

# ---------------- Probe Parser ----------------
def parse_probe(xml: str, probed_uuid: str):
    """
    Parse ProbeMatch response and update/create Scanner objects.

    Args:
        xml (str): SOAP XML response as string
        scanners (dict): Dictionary {uuid: Scanner}
        
    """
    logger.info(f"{datetime.datetime.now():%Y-%m-%d %H:%M:%S} [WSD:parse_probe] parsing probe from {probed_uuid} @ {SCANNERS[probed_uuid].ip}")
    logger.debug(f"XML:\n{xml}")
    
    SCANNERS[probed_uuid].state = STATE.PROBE_PARSING
   
    try:
        root = ET.fromstring(xml)
    except ET.ParseError as e:
        logger.error(f"[WSD:probe_parser] XML ParseError: {e}")
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
#            SCANNERS[uuid].status = ScannerStatus.ERROR
            continue

        # die Serviceadresse finden
        xaddr = None
        xaddrs_elem = pm.find(".//wsd:XAddrs", NAMESPACES)
        xaddr = pick_best_xaddr(xaddrs_elem.text.strip())

#        if uuid_elem is None or types_elem is None or xaddrs_elem is None:
        if probe_uuid is None or types is None or xaddr is None:
            logger.warning(f"[WSD:parse_probe] Incomplete ProbeMatch, skipping UUID {probe_uuid}")
            logger.warning(f"   --->  UUID: {probe_uuid}")
            logger.warning(f"   ---> TYPES: {types}")
            logger.warning(f"   ---> XADDR: {xaddr}")
            SCANNERS[probed_uuid].state = STATE.ERROR
            continue


        # neuer oder vorhandener Scanner?
        if probe_uuid not in SCANNERS:
#            SCANNERS[probe_uuid] = Scanner(uuid=probe_uuid, ip=scanner.ip, xaddr=xaddr)
            SCANNERS[probe_uuid] = Scanner(uuid=probe_uuid, ip=SCANNERS[probed_uuid].ip, xaddr=xaddr)
#            SCANNERS[probe_uuid].related_uuids.add(uuid)       # = set()
            SCANNERS[probe_uuid].state = STATE.PROBE_PARSED                       # das neue Gerät > hat die Probe bestanden, wird nun weiter konnektiert
            SCANNERS[probed_uuid].state = STATE.ONLINE                                    # das alte Gerät > ist weiterhin online, wird nicht mehr bearbeitet
#            marry_endpoints(SCANNERS[uuid], SCANNERS[probe_uuid])
            marry_endpoints(probed_uuid, probe_uuid)
            logger.info(f"[WSD:probe_parser] Discovered new scanner endpoint with {probe_uuid} @ {SCANNER[probed_uuid].ip} as child from {probed_uuid}")
        else:
            SCANNERS[probed_uuid].xaddr = xaddr
#            SCANNERS[uuid].related_uuids.add(uuid)       # = set()
            SCANNERS[probed_uuid].state = STATE.PROBE_PARSED
            logger.info(f"[WSD:probe_parser] Updated scanner {probed_uuid} -> {xaddr}")

    list_scanners()

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


# ---------------- Transfer/GET Parser ----------------
def parse_transfer_get(xml_body: bytes, tf_g_uuid):
    logger.info(f"{datetime.datetime.now():%Y-%m-%d %H:%M:%S} [WSD:parse_probe] parsing transfer_get from {tf_g_uuid} @ {SCANNERS[tf_g_uuid].ip}")
    logger.info(f"XML:\n{xml_body}")

    SCANNERS[tf_g_uuid].state = STATE.GET_PARSING
#    root = ET.fromstring(xml_body)

    try:
        root = ET.fromstring(xml_body.decode("utf-8", errors="ignore"))
        logger.info(f"extracted xml_body to root")
    except Exception as e:
        logger.debug(f"[WSD] Error while parsing transfer_get: {e}")
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
            logger.info(f"  ADDR: {addr}")
            logger.info(f" TYPES: {types}")
            if "ScannerServiceType" in types:
                SCANNERS[tf_g_uuid].services["scan"] = addr
            #elif "PrinterServiceType" in types:
            #    SCANNERS[tf_g_uuid].services["print"] = addr

    logger.info(f"   ---> FN: {SCANNERS[tf_g_uuid].friendly_name}")
    logger.info(f"   ---> SN: {SCANNERS[tf_g_uuid].serial_number}")
    logger.info(f"   ---> FW: {SCANNERS[tf_g_uuid].firmware}")

    SCANNERS[tf_g_uuid].state = STATE.GET_PARSED


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
