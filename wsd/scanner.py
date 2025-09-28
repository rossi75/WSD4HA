import datetime
import socket
import logging
import sys
from globals import SCANNERS, list_scanners, NAMESPACES, STATE, LOG_LEVEL
from config import OFFLINE_TIMEOUT

#logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')
logging.basicConfig(level=logging.LOG_LEVEL, format='[%(levelname)s] %(message)s')
logger = logging.getLogger("wsd-addon")

# ---------------- Scanner-Datenstruktur ----------------
class Scanner:
    def __init__(self, uuid, ip = "0.0.0.0", xaddr = None):
        logger.info(f"{datetime.datetime.now():%Y-%m-%d %H:%M:%S} [SCANNER:__init__] New instance of Scanner")
        self.uuid = uuid
        self.ip = ip

        # WSD Parameters
        self.xaddr = xaddr            # Service-Adresse (aus <wsd:XAddrs>)
        self.subscription_timeout = 0
        self.subscription_last_seen = None
        self.subscription_id = None
        self.subscription_ref = None
        self.destination_token = None

        # zusätzliche optionale Infos
        self.friendly_name = "NoName"
        self.mac = None
        self.firmware = None
        self.serial = None
        self.model = None
        self.manufacturer = None
        self.related_uuids = set()

        # Status
        self.first_seen = datetime.datetime.now().replace(microsecond=0)
        self.last_seen = datetime.datetime.now().replace(microsecond=0)
        self.state = STATE.DISCOVERED
        self.offline_since = None
        self.remove_after = None  # Zeitpunkt zum Löschen

        logger.debug(f"[SCANNER:__init__]  UUID: {self.uuid}")
        logger.debug(f"[SCANNER:__init__]    IP: {self.ip}")
        logger.debug(f"[SCANNER:__init__] XADDR: {self.xaddr}")

    # Scanner ist noch online
    # Aufruf mit SCANNER[uuid].update()
    def update(self):
        self.last_seen = datetime.datetime.now().replace(microsecond=0)
        self.state = STATE.ONLINE
        self.offline_since = None
        self.remove_after = None
        logger.info(f"{datetime.datetime.now():%Y-%m-%d %H:%M:%S} [SCANNER:upd] Updated timestamps for {self.friendly_name} @ {self.ip} with UUID {self.uuid}")
        logger.debug(f"   ---> new last_seen: {self.last_seen}")

    # Scannerservice ist noch online
    # Aufruf mit SCANNER[uuid].update_subscription()
#    def update_subscription(self, timeout = 3600):
    def update_subscription(self):
        self.subscription_last_seen = datetime.datetime.now().replace(microsecond=0)
        self.state = STATE.ONLINE
        self.offline_since = None
        self.remove_after = None
        logger.info(f"{datetime.datetime.now():%Y-%m-%d %H:%M:%S} [SCANNER:updsvc] Updated timestamps for scanner subscription {self.friendly_name} @ {self.ip} with UUID {self.uuid}")
        logger.info(f"   ---> new subscribtion last_seen: {self.subscription_last_seen}")

    # wird aufgerufen wenn ein Scanner offline gesetzt wird
    # Aufruf mit SCANNER[uuid].mark_offline()
    def mark_absent(self):
        self.state = STATE.ABSENT
        if not self.offline_since:
            self.offline_since = datetime.datetime.now().replace(microsecond=0)
            self.remove_after = self.offline_since + datetime.timedelta(seconds=OFFLINE_TIMEOUT)
        logger.info(f"{datetime.datetime.now():%Y-%m-%d %H:%M:%S} [SCANNER:m_offl] marked {self.friendly_name} @ {self.ip} as offline")
        logger.debug(f"   -->         state: {self.state}")
        logger.debug(f"   --> offline_since: {self.offline_since}")
        logger.debug(f"   -->  remove_after: {self.remove_after}")

# ---------------- marry two endpoints ----------------
def marry_endpoints(uuid_a: str, uuid_b: str):
    """
    Stellt sicher, dass zwei Scanner-Objekte sich gegenseitig kennen.
    """
    SCANNERS[uuid_a].related_uuids += uuid_b
    SCANNERS[uuid_b].related_uuids += uuid_a
    logger.info(f"[SCANNER:marry_EP] married UUID {uuid_a} with {uuid_b}")
