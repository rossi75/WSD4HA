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
#from scanner import list_scanners
#from globals import list_scanners
from globals import SCANNERS, list_scanners 

NAMESPACES = {
    "soap": "http://www.w3.org/2003/05/soap-envelope",
    "wsd": "http://schemas.xmlsoap.org/ws/2005/04/discovery",
    "wsa": "http://schemas.xmlsoap.org/ws/2004/08/addressing"
}

# ----------------- To Do -----------------
# - Drucker oder Scanner name übernehmen
# - passende antwort schreiben
# + Logs mit D/T
# - scanauftrag entgegennehmen
# - webserver zum laufen bekommen
# + nach einem neuzugang die liste anzeigen
# + nach einem abgang diesen im log ausführlich ausgeben
# + neuer scanner wird zu oft erkannt

# ---------------- Logging ----------------
logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')
logger = logging.getLogger("wsd-addon")

# ---------------- Optionen aus Environment ----------------
#WSD_SCAN_FOLDER = Path(os.environ.get("WSD_SCAN_FOLDER", "/share/scans"))
SCAN_FOLDER = Path(os.environ.get("WSD_SCAN_FOLDER", "/share/scans"))
SCAN_FOLDER.mkdir(parents=True, exist_ok=True)
#WSD_MAX_FILES = int(os.environ.get("WSD_MAX_FILES", 5))
#WSD_HTTP_PORT = int(os.environ.get("WSD_HTTP_PORT", 8080))
#WSD_OFFLINE_TIMEOUT = int(os.environ.get("WSD_OFFLINE_TIMEOUT", 300))  # Sekunden
#WSD_HTTP_PORT = int(os.environ.get("HTTP_PORT", 8080))
HTTP_PORT = 8110
MAX_FILES = int(os.environ.get("WSD_MAX_FILES", 5))
OFFLINE_TIMEOUT = int(os.environ.get("WSD_OFFLINE_TIMEOUT", 300))  # Sekunden

logger.info(f"**********************************************************")
logger.info(f"Starting up WSD Scanner Service")
logger.info(f"{datetime.datetime.now():%d.%m.%Y, %H:%M:%S}")
logger.info(f"---------------------  Configuration  ---------------------")
logger.info(f"Scan-Path: {SCAN_FOLDER}")
logger.info(f"max scanned files to show: {MAX_FILES}")
logger.info(f"HTTP-Port for UI: {HTTP_PORT}")
if OFFLINE_TIMEOUT < 120:
    logger.warning("OFFLINE_TIMEOUT zu klein, auf 120 gesetzt")
    OFFLINE_TIMEOUT = 120
OFFLINE_TIMEOUT = 120
logger.info(f"Offline Timeout: {OFFLINE_TIMEOUT}s")

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
        logger.warning(f"{datetime.datetime.now():%Y-%m-%d %H:%M:%S} [*] Could not obtain Host IP: {e}")
        return "undefined"

LOCAL_IP = get_local_ip()

# ---------------- Portprüfung ----------------
def check_port(port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.bind(('', port))
            return True
        except OSError:
            return False

if not check_port(HTTP_PORT):
    logger.error(f"[*] Port {HTTP_PORT} is already in use!")
    sys.exit(1)
else:
    logger.info(f"Statusserver reachable at {LOCAL_IP}:{HTTP_PORT}")

