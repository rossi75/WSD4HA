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
import uuid
#from globals import SCANNERS, list_scanners, FROM_UUID, USER_AGENT, LOG_LEVEL
from globals import SCANNERS, FROM_UUID, USER_AGENT, LOG_LEVEL, SCAN_FOLDER, STARTUP_DT, logger
#from globals import SCANNERS, SCAN_JOBS, NAMESPACES, STATE, logger
from tools import list_scanners, check_port, get_local_ip

# ----------------- To Do -----------------
# + Drucker oder Scanner name übernehmen
# + passende antwort schreiben
# + Logs mit D/T
# - scanauftrag entgegennehmen
# - Daten in ne Datei schreiben
# - Dateiliste auslesen
# + webserver zum laufen bekommen
# + nach einem neuzugang die liste anzeigen
# + nach einem abgang diesen im log ausführlich ausgeben
# + neuer scanner wird zu oft erkannt

# ---------------- Logging ----------------
#LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO").upper()
#LOG_LEVEL = os.environ.get("LOG_LEVEL", "DEBUG").upper()
# dynamisches loglevel
#logging.basicConfig(
#    level=getattr(logging, LOG_LEVEL, logging.INFO),
#    format="[%(levelname)s] %(message)s",
#)
#    format="%(asctime)s [%(levelname)s] %(message)s",
# festes Loglevel
#logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')
#logging.basicConfig(level=logging.DEBUG, format='[%(levelname)s] %(message)s')
#logging.basicConfig(level=logging.LOG_LEVEL, format='[%(levelname)s] %(message)s')
#logging.basicConfig(level=LOG_LEVEL, format='[%(levelname)s] %(message)s')
#logger = logging.getLogger("wsd-addon")

STARTUP_DT = datetime.datetime.now().replace(microsecond=0)

logger.info(f" ")
#logger.info(f"***********************************************************")
#logger.info(f"*    Starting up WSD Scanner Service for Home Assistant   *")
#logger.info(f"*                                                         *")
logger.info(f"***************************************************************************************************************")
logger.info(r"*                                                                                                             *")
logger.info(r"*     __        ______  ____    ____                                    ____                  _               *")
logger.info(r"*     \ \      / / ___||  _ \  / ___|  ___ __ _ _ __  _ __   ___ _ __  / ___|  ___ _ ____   _(_) ___ ___      *")
logger.info(r"*      \ \ /\ / /\___ \| | | | \___ \ / __/ _` | '_ \| '_ \ / _ \ '__| \___ \ / _ \ '__\ \ / / |/ __/ _ \     *")
logger.info(r"*       \ V  V /  ___) | |_| |  ___) | (_| (_| | | | | | | |  __/ |     ___) |  __/ |   \ V /| | (_|  __/     *")
logger.info(r"*       _\_/\_/  |____/|____/  |____/ \___\__,_|_| |_|_|_|_|\___|_|  _ |____/ \___|_|    \_/ |_|\___\___|     *")
logger.info(r"*      / _| ___  _ __  | | | | ___  _ __ ___   ___     / \   ___ ___(_)___| |_ __ _ _ __ | |_                 *")
logger.info(r"*     | |_ / _ \| '__| | |_| |/ _ \| '_ ` _ \ / _ \   / _ \ / __/ __| / __| __/ _` | '_ \| __|                *")
logger.info(r"*     |  _| (_) | |    |  _  | (_) | | | | | |  __/  / ___ \\__ \__ \ \__ \ || (_| | | | | |_                 *")
logger.info(r"*     |_|  \___/|_|    |_| |_|\___/|_| |_| |_|\___| /_/   \_\___/___/_|___/\__\__,_|_| |_|\__|                *")
logger.info(r"*                                                                                                             *")
logger.info(f"*                                             {STARTUP_DT:%d.%m.%Y, %H:%M:%S}                                            *")
logger.info(f"***************************************************************************************************************")
logger.info(f"*                                                Configuration                                                *")
logger.info(f"***************************************************************************************************************")
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
    logger.warning(f"HTTP-Port Reset to fallback value 8110 (should never reach this point)")
logger.info(f"HTTP-Port for UI: {HTTP_PORT}")

# ---------------- NOTIFY-Port ----------------
raw = int(os.environ.get("NOTIFY_PORT", 5357))
logger.debug(f"NOTIFY-Port from Environment: {raw}")
try:
    NOTIFY_PORT = int(raw)  # Sekunden
except ValueError:
    NOTIFY_PORT = 5357  # Fallback vom Fallback
    logger.warning(f"NOTIFY-Port Reset to fallback value 5357 (should never reach this point)")
logger.info(f"NOTIFY-Port for Scan Events: {NOTIFY_PORT}")

# ---------------- User-Agent ----------------
logger.info(f"User-Agent: {USER_AGENT}")

# ---------------- Local IP ----------------
LOCAL_IP = get_local_ip()
logger.info(f"Local IP: {LOCAL_IP}")

# ---------------- UUID ----------------
FROM_UUID = f"{uuid.uuid4()}"
#logger.info("[GLOBAL:uuid] set FROM_UUID: {FROM_UUID}")
logger.info(f"FROM_UUID: {FROM_UUID}")

# ---------------- Display Entry ----------------
raw = os.environ.get("DISPLAYNAME", "Home Assistant")
logger.debug(f"Display Entry from Environment: {raw}")
try:
    DISPLAY = raw  # Sekunden
except ValueError:
    DISPLAY = "Scan to Homeassistant FB"  # Fallback vom Fallback
    logger.warning(f"Reset to fallback Display setting (should never reach this point)")
logger.info(f"Destinations Entry on Scanner: {DISPLAY}")

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
    logger.warning(f"Reset to fallback value (should never reach this point)")
logger.info(f"max scanned files to show: {MAX_FILES}")


#
#
# --------------------------------------------------
# ---------------- END OF CONFIG.PY ----------------
