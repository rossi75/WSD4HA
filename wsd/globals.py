# to be imported by all files
#import datetime
#import socket
import logging
import sys
#import os

# -----------------  global configuration  -----------------
logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')
logger = logging.getLogger("wsd-addon")

# -----------------  global configuration  -----------------
#from globals import SCANNERS, list_scanners, OFFLINE_TIMEOUT, SCAN_FOLDER, MAX_FILES

#OFFLINE_TIMEOUT = int(os.environ.get("OFFLINE_TIMEOUT", 300))  # Sekunden
#SCAN_FOLDER = Path(os.environ.get("SCAN_FOLDER", "/share/scans"))
#SCAN_FOLDER.mkdir(parents=True, exist_ok=True)
#MAX_FILES = int(os.environ.get("MAX_FILES", 5))


# -----------------  define SCANNERS dict  -----------------
SCANNERS = {}

# -----------------  Nach jedem Update: Liste loggen  -----------------
def list_scanners():
    logger.info("[SCANNERS] registered Scanners:")
#        for s in SCANNERS.values():
#            logger.info(f"  - {s.name} ({s.ip}, {s.uuid})")
    for i, s in enumerate(SCANNERS.values(), start=1):
        logger.info(f"[{i}] {s.name} ({s.ip}) UUID={s.uuid} Online={s.online}")
