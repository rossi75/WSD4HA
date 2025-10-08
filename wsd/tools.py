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
# def find_scanner_from_notify(xml_body: str):
#
#
# ----------------------------------------------------------------------------

from globals import SCANNERS
import xml.etree.ElementTree as ET

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

# ---------------- marry two endpoints ----------------
def marry_endpoints(uuid_a: str, uuid_b: str):
    """
    Stellt sicher, dass zwei Scanner-Objekte sich gegenseitig kennen.
    """
    SCANNERS[uuid_a].related_uuids += uuid_b
    SCANNERS[uuid_b].related_uuids += uuid_a
    logger.info(f"[TOOLS:marry_EP] married UUID {uuid_a} with {uuid_b}")


def find_scanner_from_notify(xml_body: str):
    """Analysiert eine eingehende Notify-Message und findet die zugehörige Scanner-UUID"""

    try:
        root = ET.fromstring(xml_body)
    except ET.ParseError:
        logger.warning("[TOOLS:find_scanner] XML parse error")
        return None

    # Versuch 1: Identifier
    ident_elem = root.find(".//wse:Identifier", NAMESPACES)
    identifier = ident_elem.text.strip() if ident_elem is not None else None

    # Versuch 2: DestinationToken
    token_elem = root.find(".//wscn:DestinationToken", NAMESPACES)
    token = token_elem.text.strip() if token_elem is not None else None

    # Versuch 3: IP-Adresse (Fallback)
    # (wird besser im Handler gemacht, z.B. request.remote)
    
    for uuid, scanner in SCANNERS.items():
        logger.info(f"testing {uuid} and/or {scanner}")
        if (identifier and getattr(scanner, "subscription_identifier", None) == identifier) \
           or (token and getattr(scanner, "destination_token", None) == token):
            logger.info(f"[TOOLS:find_scanner] Found relation for notify point : {SCANNERS[uuid].friendly_name} @ {scanner.friendly_name}) erkannt")
            return uuid

    logger.warning(f"[TOOLS:find_scanner] Could not find any Scanner with notify point =  or Identifier = {identifier} or Token = {token}")
    return None
