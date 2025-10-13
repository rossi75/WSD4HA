# ------------------------------- Helper/Tools -------------------------------
# def check_port(port)
#     checks if port is available or occupied
#     return true if port is available
#     returns false if port is occupied
# 
# def get_local_ip()
#     returns the local IP. not hardened against a network change !!
#
# def pick_best_xaddr(xaddrs: str) -> str:
#
#
# def list_scanners():
#
#
# def marry_endpoints(uuid_a: str, uuid_b: str):
#
#
# def find_scanner_by_endto_addr(endto_addr: str):
#
#
# def save_scanned_image(scanner_name: str, image_bytes: bytes):
#
#
# ----------------------------------------------------------------------------

import datetime
import logging
import re
import socket
import xml.etree.ElementTree as ET
#from globals import SCANNERS, LOG_LEVEL, NAMESPACES
from globals import SCANNERS, NAMESPACES, logger

#logging.basicConfig(level=LOG_LEVEL, format='[%(levelname)s] %(message)s')
#logger = logging.getLogger("wsd-addon")



# ---------------- lokale IP abfragen ----------------
def get_local_ip():
    try:
        # UDP-Socket zu einer externen Adresse öffnen (wird nicht gesendet)
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))  # Google DNS, nur für Routing
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        logger.warning(f"[CONFIG] Could not obtain Host IP: {e}")
        return "undefined"


# ---------------- Portprüfung ----------------
def check_port(port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.bind(('', port))
            return True
        except OSError:
            return False


# ---------------- Pick Best XADDR from String ----------------
def pick_best_xaddr(xaddrs: str) -> str:
    """
    Wählt aus einer Liste von XAddrs den besten Kandidaten:
    - bevorzugt IPv4
    - ignoriert IPv6, wenn IPv4 vorhanden ist
    - nimmt den Hostnamen, falls keine IP vorhanden ist
    """
    logger.debug(f"{datetime.datetime.now():%Y-%m-%d %H:%M:%S}[TOOLS:xaddr] received {xaddrs}")
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

    logger.debug(f"[TOOLS:xaddr] extracted {ipv4 or hostname or None}")
    return ipv4 or hostname or None

# -----------------  Nach jedem Update: Liste loggen  -----------------
def list_scanners():
    if SCANNERS:
        logger.info("   ------>   known Scanners   <------")
        for i, s in enumerate(SCANNERS.values(), start=1):
            logger.info(f"   [{i}] {s.friendly_name or s.uuid} @ {s.ip}")
            logger.debug(f"       --->      XADDR: {s.xaddr}")
            logger.info(f"       --->     Status: {s.state.value}")
            logger.debug(f"       ---> first_seen: {s.last_seen}")
            logger.debug(f"       --->  last_seen: {s.first_seen}")
    else:
        logger.info("no known Scanners in list")  

# ---------------- parse w3c timer ----------------
# parse_w3c_duration("PT1H")   # -> 3600
def calc_w3c_duration(duration: str) -> int:
    """
    Wandelt W3C/ISO8601 Duration (z.B. 'PT1H30M') in Sekunden um.
    Unterstützt Tage, Stunden, Minuten, Sekunden.
    """
    
    logger.debug(f"[PARSE:w3c_dur] duration to calculate: {duration}")
    
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
    
    logger.debug(f"   ---> d: {d}")
    logger.debug(f"   ---> seconds: {seconds}")

    return seconds


# ---------------- marry two endpoints ----------------
def marry_endpoints(uuid_a: str, uuid_b: str):
    """
    Stellt sicher, dass zwei Scanner-Objekte sich gegenseitig kennen.
    """
    SCANNERS[uuid_a].related_uuids += uuid_b
    SCANNERS[uuid_b].related_uuids += uuid_a
    logger.info(f"[TOOLS:marry_EP] married UUID {uuid_a} with {uuid_b}")


# ---------------- which scanner notified to end_to? ----------------
def find_scanner_by_endto_addr(endto_addr: str):
    """
    Findet den Scanner anhand des EndTo-Identifier-Teils (z.B. '4de2dca3-c3cf-4fff-8b66-bbfac4c3bd50').
    """

    logger.debug(f"[TOOLS:find_scanner] searching for {endto_addr} in all known scanners")

    endto_addr = endto_addr.strip().lstrip('/')  # führenden Slash entfernen
    logger.debug(f"   ---> endto_addr: {endto_addr}")

    for uuid, scanner in SCANNERS.items():
        endto_compare = getattr(scanner, "end_to_addr", "")
        endto_compare = endto_compare.split('/')[-1]
        logger.debug(f"   ---> endto_comp: {endto_compare}")
        if endto_compare and endto_addr in endto_compare:    # Teilstring-Suche
            logger.debug(f"[TOOLS:find_scanner] match found for {SCANNERS[uuid].friendly_name or uuid} @ {SCANNERS[uuid].ip}")
            return uuid

    logger.warning(f"[TOOLS:find_scanner] could not find {endto_addr} in any known scanners")
    return None


# ---------------- which scanner notified to end_to? ----------------
def save_scanned_image(scanner_name: str, image_bytes: bytes):
    """
    Speichert das empfangene Scan-Image auf der Festplatte mit
    - automatisch erkannter Dateiendung
    - bereinigtem Dateinamen
    - Zeitstempel
    """
    if not image_bytes:
        logger.warning("[SAVE] No image data to save")
        return None

    # Dateityp erkennen
    header = image_bytes[:8]
    if header.startswith(b"\xFF\xD8\xFF"):
        ext = ".jpg"
    elif header.startswith(b"\x89PNG"):
        ext = ".png"
    elif header.startswith(b"II*\x00") or header.startswith(b"MM\x00*"):
        ext = ".tiff"
    elif header.startswith(b"%PDF"):
        ext = ".pdf"
    else:
        ext = ".bin"  # Fallback

    # Friendly-Name säubern
    safe_name = re.sub(r"[^A-Za-z0-9_\-]", "_", scanner_name.strip())

    # Zeitstempel
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

    # Zielpfad
    filename = f"/scans/{safe_name}_{timestamp}{ext}"
    os.makedirs(os.path.dirname(filename), exist_ok=True)

    # Datei speichern
    try:
        with open(filename, "wb") as f:
            f.write(image_bytes)
        logger.info(f"[SAVE] Image saved: {filename}")
        return filename
    except Exception as e:
        logger.error(f"[SAVE] Could not save image: {e}")
        return None

#
#
# --------------------------------------------------
# ---------------- END OF TOOLS.PY ----------------
