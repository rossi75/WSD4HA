import datetime
import socket
import logging
import sys
from globals import SCANNERS, list_scanners, NAMESPACES, STATE
from config import OFFLINE_TIMEOUT


logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')
logger = logging.getLogger("wsd-addon")

# ---------------- Scanner-Datenstruktur ----------------
class Scanner:
    def __init__(self, uuid, ip="0.0.0.0", xaddr=None):
        logger.info(f"{datetime.datetime.now():%Y-%m-%d %H:%M:%S} [SCANNER:__init__] New instance of Scanner with:")
        self.uuid = uuid
        self.ip = ip

        # WSD Parameters
        self.xaddr = xaddr            # Service-Adresse (aus <wsd:XAddrs>)
        self.subscription_id = None
        self.subscription_expires = None

        # zusätzliche optionale Infos
        self.friendly_name = "NoName"
        self.mac = None
        self.firmware = None
        self.serial = None
        self.model = None
        self.manufacturer = None
        self.related_uuids = set()

        # Status
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
        logger.info(f"{datetime.datetime.now():%Y-%m-%d %H:%M:%S} [SCANNER:upd] Updated timestamps for {self.friendly_name} ({self.ip}) with UUID {self.uuid}")
        logger.debug(f"   --> new last_seen: {self.last_seen}")

    # wird aufgerufen wenn ein Scanner offline gesetzt wird
    # Aufruf mit SCANNER[uuid].mark_offline()
    def mark_absent(self):
        self.state = STATE.ABSENT
        if not self.offline_since:
            self.offline_since = datetime.datetime.now().replace(microsecond=0)
            self.remove_after = self.offline_since + datetime.timedelta(seconds=OFFLINE_TIMEOUT)
        logger.info(f"{datetime.datetime.now():%Y-%m-%d %H:%M:%S} [SCANNER:m_offl] marked {self.friendly_name} ({self.ip}) with UUID {self.uuid} as offline")
        logger.debug(f"   -->         state: {self.state}")
        logger.debug(f"   --> offline_since: {self.offline_since}")
        logger.debug(f"   -->  remove_after: {self.remove_after}")

    def add_related_uuid(self, other_uuid: str):
        logger.info(f"[SCANNER:relate] marry UUID {self.uuid} with {other_uuid}")
        """
        Verknüpft diesen Scanner mit einer weiteren UUID.
        """
        if other_uuid and other_uuid != self.uuid:
            self.related_uuids.add(other_uuid)
