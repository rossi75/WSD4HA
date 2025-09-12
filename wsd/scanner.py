import datetime
import socket
import logging
import sys
from globals import SCANNERS, list_scanners 
#from config import WSD_OFFLINE_TIMEOUT
from config import OFFLINE_TIMEOUT
#from config import WSD_HTTP_PORT, WSD_OFFLINE_TIMEOUT, WSD_SCAN_FOLDER

NAMESPACES = {
    "soap": "http://www.w3.org/2003/05/soap-envelope",
    "wsd": "http://schemas.xmlsoap.org/ws/2005/04/discovery",
    "wsa": "http://schemas.xmlsoap.org/ws/2004/08/addressing"
}

logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')
logger = logging.getLogger("wsd-addon")

# ---------------- Scanner-Datenstruktur ----------------
class Scanner:
    def __init__(self, name, ip, mac=None, uuid=None, formats=None, location=None, max_age=OFFLINE_TIMEOUT, xaddr=None):
        self.name = name
        self.ip = ip
        self.mac = mac
        self.uuid = uuid
        self.formats = formats or [] # unnötg?
        self.xaddr = xaddr            # Service-Adresse (aus <wsd:XAddrs>)

        # zusätzliche Infos
        self.friendly_name = None
        self.firmware = None
        self.serial = None
        self.model = None
        self.manufacturer = None
        self.location = location

        # Status
        #self.last_seen = datetime.datetime.now()
        self.last_seen = datetime.datetime.now() - datetime.timedelta(seconds=max_age // 2) # last_seen so zurücksetzen, dass wir "halbzeit" erreicht haben
        self.max_age = max_age
        self.online = True
        self.offline_since = None
        self.remove_after = None  # Zeitpunkt zum Löschen


    # Scanner ist noch online
    # Aufruf mit SCANNER[uuid].update()
    def update(self, max_age=OFFLINE_TIMEOUT):
        self.last_seen = datetime.datetime.now()
        self.max_age = max_age
        self.online = True
        self.offline_since = None
        self.remove_after = None
        logger.info(f"{datetime.datetime.now():%Y-%m-%d %H:%M:%S} [SCANNER:upd] {self.ip} ({self.friendly_name or self.name})")
        logger.info(f"   --> new last_seen: {self.last_seen}")

    # wird aufgerufen wenn ein Scanner offline gesetzt wird
    # Aufruf mit SCANNER[uuid].update()
    def mark_offline(self):
        if self.online:
            self.online = False
        if not self.offline_since:
            self.offline_since = datetime.datetime.now()
            self.remove_after = self.offline_since + datetime.timedelta(seconds=self.max_age)
        logger.info(f"{datetime.datetime.now():%Y-%m-%d %H:%M:%S} [SCANNER:m_offl] {self.ip} ({self.friendly_name or self.name})")


    # Fragt Scanner-Metadaten per WS-Transfer/Get ab
    # def fetch_metadata(self):
#    async def fetch_metadata(self):
#    async def fetch_metadata(uuid: str):
    async def fetch_metadata(self):
        logger.info(f"[META] searching for UUID {self.uuid}")
        if self.uuid not in SCANNERS:
            logger.info(f"{datetime.datetime.now():%Y-%m-%d %H:%M:%S} [META] could not find Scanner with uuid: {self.uuid})")
            return

        logger.info(f"[META]   ---> xaddr: {self.xaddr} ")
        if not self.xaddr:
            logger.warning(f"[META] missing xaddr element in struct!")
            logger.warning(f"[META]    --> xaddr = {self.xaddr}")
            return

        logger.info(f"[META] trying to request Metadata for {self.uuid}")

        # Minimaler SOAP-Request für "Get"
        soap_request = f"""<?xml version="1.0" encoding="utf-8"?>
        <soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope"
                       xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing">
            <soap:Header>
                <wsa:To>{self.xaddr}</wsa:To>
                <wsa:Action>http://schemas.xmlsoap.org/ws/2004/09/transfer/Get</wsa:Action>
                <wsa:MessageID>urn:uuid:{self.uuid or datetime.datetime.now().timestamp()}</wsa:MessageID>
            </soap:Header>
            <soap:Body />
        </soap:Envelope>"""

        headers = {
            "Content-Type": "application/soap+xml; charset=utf-8"
        }

        logger.info(f" [Scanner:{self.ip}] Sende Metadata-Request an {self.xaddr}")
        r = httpx.post(self.xaddr, data=soap_request, headers=headers, timeout=5.0)

        if r.status_code != 200:
            raise RuntimeError(f"HTTP {r.status_code} von {self.xaddr}")

        root = ET.fromstring(r.text)

        # FriendlyName
        logger.info(f"   ---> Trying to get friendly name")
        fn = root.find(".//{http://schemas.xmlsoap.org/ws/2006/02/devprof}FriendlyName")
        logger.info(f"   ---> fn: {fn}")
        if fn is not None and fn.text:
            self.name = fn.text.strip()
        logger.info(f"      ---> .name: {self.name}")

        # FirmwareVersion
        logger.info(f"   ---> Trying to get Firmware Version")
        fw = root.find(".//{http://schemas.xmlsoap.org/ws/2006/02/devprof}FirmwareVersion")
        logger.info(f"   ---> fw: {fw}")
        if fw is not None:
            self.firmware = fw.text.strip()
        logger.info(f"      ---> .firmware: {self.firmware}")

        # SerialNumber
        logger.info(f"   ---> Trying to get Serial Number")
        sn = root.find(".//{http://schemas.xmlsoap.org/ws/2006/02/devprof}SerialNumber")
        logger.info(f"   ---> sn: {sn}")
        if sn is not None:
            self.serial = sn.text.strip()
        logger.info(f"      ---> .serial: {self.serial}")

        # Model
        logger.info(f"   ---> Trying to get model name")
        model = root.find(".//{http://schemas.xmlsoap.org/ws/2006/02/devprof}ModelName")
        logger.info(f"   ---> model: {model}")
        if model is not None:
            self.model = model.text.strip()
        logger.info(f"      ---> .model: {self.model}")

        # Manufacturer
        logger.info(f"   ---> Trying to get Manufacturer")
        mf = root.find(".//{http://schemas.xmlsoap.org/ws/2006/02/devprof}Manufacturer")
        logger.info(f"   ---> mf: {mf}")
        if mf is not None:
            self.manufacturer = mf.text.strip()
        logger.info(f"      ---> .manufacturer: {self.manufacturer}")

#        logger.info(f"{datetime.datetime.now():%Y-%m-%d %H:%M:%S} [Scanner:{self.ip}] Metadaten: {self.name} | FW={self.firmware} | SN={self.serial}")
        logger.info(f"fetched additional Metadata from {self.xaddr}")
        logger.info(f"    -->         Name: {self.friendly_name}")
        logger.info(f"    -->     Firmware: {self.firmware}")
        logger.info(f"    -->       Serial: {self.serial}")
        logger.info(f"    -->        Model: {self.model}")
        logger.info(f"    --> Manufacturer: {self.manufacturer}")
