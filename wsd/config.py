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
from globals import SCANNERS, list_scanners, FROM_UUID


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
# + webserver zum laufen bekommen
# + nach einem neuzugang die liste anzeigen
# + nach einem abgang diesen im log ausführlich ausgeben
# + neuer scanner wird zu oft erkannt

# ---------------- Logging ----------------
LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO").upper()
LOG_LEVEL = os.environ.get("LOG_LEVEL", "DEBUG").upper()
# dynamisches loglevel
#logging.basicConfig(
#    level=getattr(logging, LOG_LEVEL, logging.INFO),
#    format="[%(levelname)s] %(message)s",
#)
#    format="%(asctime)s [%(levelname)s] %(message)s",
# festes Loglevel
#logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')
logging.basicConfig(level=logging.DEBUG, format='[%(levelname)s] %(message)s')

logger = logging.getLogger("wsd-addon")

logger.info(f" ")
logger.info(f"***********************************************************")
logger.info(f"Starting up WSD Scanner Service")
logger.info(f"{datetime.datetime.now():%d.%m.%Y, %H:%M:%S}")
logger.info(f"***********************************************************")
logger.info(f"---------------------  Configuration  ---------------------")
# ---------------- Optionen aus Environment ----------------
# ---------------- Logging ----------------
logger.info(f"Loglevel: {LOG_LEVEL}")

# ---------------- HTTP-Port ----------------
raw = int(os.environ.get("HTTP_PORT", 8110))
logger.debug(f"HTTP-Port from Environment: {raw}")
try:
    HTTP_PORT = int(raw)  # Sekunden
except ValueError:
    HTTP_PORT = 8110  # Fallback vom Fallback
    logger.debug(f"Reset to fallback Port (should never reach this point)")
logger.info(f"HTTP-Port for UI: {HTTP_PORT}")


# ---------------- HTTP-Port ----------------
FROM_UUID = f"urn:uuid:{uuid.uuid4()}"
#logger.info("[GLOBAL:uuid] set FROM_UUID: {FROM_UUID}")
logger.info("set FROM_UUID: {FROM_UUID}")

# ---------------- OFFLINE_TIMEOUT ----------------
raw = int(os.environ.get("OFFLINE_TIMEOUT", 300))  # Sekunden
logger.debug(f"OFFLINE_TIMEOUT from Environment: {raw}")
try:
    OFFLINE_TIMEOUT = int(raw)  # Sekunden
except ValueError:
    OFFLINE_TIMEOUT = 300  # Fallback vom Fallback
    logger.debug(f"Reset to fallback Timeout (should never reach this point)")
if OFFLINE_TIMEOUT < 120:
    OFFLINE_TIMEOUT = 120
    logger.warning("OFFLINE_TIMEOUT too small, set to minimal value 120 seconds")
logger.info(f"Offline Timeout: {OFFLINE_TIMEOUT}s")

# ---------------- SCAN-Folder Path ----------------
SCAN_FOLDER = Path(os.environ.get("SCAN_FOLDER", "/share/scans"))
SCAN_FOLDER.mkdir(parents=True, exist_ok=True)
logger.info(f"Scan-Path: {SCAN_FOLDER}")

# ---------------- Max Files to show in GUI ----------------
raw = int(os.environ.get("MAX_FILES", 50))
logger.debug(f"MAX-Files from Environment: {raw}")
try:
    MAX_FILES = int(raw)
except ValueError:
    MAX_FILES = 50 # Fallback vom Fallback
    logger.debug(f"Reset to fallback value (should never reach this point)")
logger.info(f"max scanned files to show: {MAX_FILES}")

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
    logger.error(f"[CONFIG] Port {HTTP_PORT} is already in use!")
    sys.exit(1)
else:
    logger.info(f"Statusserver reachable at {LOCAL_IP}:{HTTP_PORT}")

