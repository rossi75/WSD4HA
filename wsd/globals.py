# to be imported by all files
#import datetime
#import socket
import logging
import sys
from enum import Enum
#import os

# -----------------  Logging  -----------------
logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')
logger = logging.getLogger("wsd-addon")

# -----------------  global configuration  -----------------
#OFFLINE_TIMEOUT = int(os.environ.get("OFFLINE_TIMEOUT", 300))  # Sekunden
#SCAN_FOLDER = Path(os.environ.get("SCAN_FOLDER", "/share/scans"))
#SCAN_FOLDER.mkdir(parents=True, exist_ok=True)
#MAX_FILES = int(os.environ.get("MAX_FILES", 5))

# -----------------  define SCANNERS dict  -----------------
SCANNERS = {}

# -----------------  define NAMESPACE  -----------------
NAMESPACES = {
    "soap": "http://www.w3.org/2003/05/soap-envelope",
    "wsa": "http://schemas.xmlsoap.org/ws/2004/08/addressing",
    "wsd": "http://schemas.xmlsoap.org/ws/2005/04/discovery",
    "wse": "http://schemas.xmlsoap.org/ws/2004/08/eventing",
    "wscn": "http://schemas.microsoft.com/windows/2006/08/wdp/scan"  # optional
}

# -----------------  define ScannerStati  -----------------
class ScannerStatus(str, Enum):
    DISCOVERED = "discovered"
    PROBING = "probing"
    PROBE_PARSING = "parsing_probe"
    PROBE_PARSED = "probe_parsed"
    GET_PENDING = "get_in_progress"
    GET_PARSING = "parsing_get"
    GET_PARSED = "get_parsed"
    ONLINE = "online"
    ABSENT = "absent"
    TO_REMOVE = "to_remove"
    ERROR = "error"

# -----------------  Nach jedem Update: Liste loggen  -----------------
def list_scanners():
    logger.info("[SCANNERS] registered Scanners:")

    for i, s in enumerate(SCANNERS.values(), start=1):
        logger.info(f"[{i}] {s.friendly_name} IP={s.ip} UUID={s.uuid}")
        logger.info(f"[{i}] {s.friendly_name} IP={s.ip} UUID={s.uuid} State={s.state.value}")
        logger.info(f"      --->     XADDR: {s.xaddr}")
        logger.info(f"      ---> last_seen: {s.last_seen}")
        logger.info(f"      --->    Status: {s.state.value}")
