# to be imported by all files
#import datetime
#import socket
import logging
import sys

logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')
logger = logging.getLogger("wsd-addon")

# -----------------  define SCANNERS dict  -----------------
SCANNERS = {}

# -----------------  Nach jedem Update: Liste loggen  -----------------
def list_scanners():
    logger.info("[SCANNERS] registered Scanners:")
#        for s in SCANNERS.values():
#            logger.info(f"  - {s.name} ({s.ip}, {s.uuid})")
    for i, s in enumerate(SCANNERS.values(), start=1):
        logger.info(f"[{i}] {s.name} ({s.ip}) UUID={s.uuid} Online={s.online}")
