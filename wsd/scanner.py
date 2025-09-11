import datetime
import socket
import logging
import sys
from state import SCANNERS
from config import WSD_OFFLINE_TIMEOUT
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
    def __init__(self, name, ip, mac=None, uuid=None, formats=None, location=None, max_age=WSD_OFFLINE_TIMEOUT, xaddr=""):
        self.name = name
        self.ip = ip
        self.mac = mac
        self.uuid = uuid
        self.formats = formats or []
        self.location = location
        self.xaddr = xaddr            # Service-Adresse (aus <wsd:XAddrs>)
    
        # zusätzliche Infos
        self.friendly_name = None
        self.firmware = None
        self.serial = None
        self.model = None
        self.manufacturer = None

        # Status
        self.last_seen = datetime.datetime.now()
        self.max_age = max_age
        self.online = True
        self.offline_since = None
        self.remove_after = None  # Zeitpunkt zum Löschen
   
        # gleich beim Erstellen Metadaten abrufen (falls Adresse bekannt)
#        if self.xaddr:
#            try:
#                self.fetch_metadata()
#            except Exception as e:
#                logger.warning(f"[Scanner:{self.ip}] Konnte Metadaten nicht abrufen: {e}")

    def update(self, max_age=WSD_OFFLINE_TIMEOUT):
        self.last_seen = datetime.datetime.now()
        self.max_age = max_age
        self.online = True
        self.offline_since = None
        self.remove_after = None

    # Fragt Scanner-Metadaten per WS-Transfer/Get ab
    # def fetch_metadata(self):
#    async def fetch_metadata(self):
    async def fetch_metadata(uuid: str):
        scanner = SCANNERS.get(uuid)

        if scanner:
        #    await scanner.fetch_metadata()
            logger.info(f"[META] found Scanner with UUID {uuid}")
        else:
            logger.warning(f"[META] no Scanner found with UUID {uuid}")
            return
        
        if not scanner.xaddr:
            logger.warning(f"[META]] missing .xaddr element !")
            return

        logger.info(f"[META]] trying to request Metadata for {uuid}")

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

        logger.info(f"{datetime.datetime.now():%Y-%m-%d %H:%M:%S} [Scanner:{self.ip}] Sende Metadata-Request an {self.xaddr}")
        r = httpx.post(self.xaddr, data=soap_request, headers=headers, timeout=5.0)

        if r.status_code != 200:
            raise RuntimeError(f"HTTP {r.status_code} von {self.xaddr}")

        root = ET.fromstring(r.text)

        # FriendlyName
        logger.info(f"{datetime.datetime.now():%Y-%m-%d %H:%M:%S} [Scanner:{self.ip}] --> Trying to get friendly name")
        fn = root.find(".//{http://schemas.xmlsoap.org/ws/2006/02/devprof}FriendlyName")
        logger.info(f"{datetime.datetime.now():%Y-%m-%d %H:%M:%S} --> fn: {fn}")
        if fn is not None and fn.text:
            self.name = fn.text.strip()
        logger.info(f"{datetime.datetime.now():%Y-%m-%d %H:%M:%S} --> self.name: {self.name}")

        # FirmwareVersion
        logger.info(f"{datetime.datetime.now():%Y-%m-%d %H:%M:%S} [Scanner:{self.ip}] --> Trying to get Firmware Version")
        fw = root.find(".//{http://schemas.xmlsoap.org/ws/2006/02/devprof}FirmwareVersion")
        logger.info(f"{datetime.datetime.now():%Y-%m-%d %H:%M:%S} --> fw: {fw}")
        if fw is not None:
            self.firmware = fw.text.strip()
        logger.info(f"{datetime.datetime.now():%Y-%m-%d %H:%M:%S} --> self.name: {self.firmware}")

        # SerialNumber
        logger.info(f"{datetime.datetime.now():%Y-%m-%d %H:%M:%S} [Scanner:{self.ip}] --> Trying to get Serial Number")
        sn = root.find(".//{http://schemas.xmlsoap.org/ws/2006/02/devprof}SerialNumber")
        logger.info(f"{datetime.datetime.now():%Y-%m-%d %H:%M:%S} --> sn: {sn}")
        if sn is not None:
            self.serial = sn.text.strip()
        logger.info(f"{datetime.datetime.now():%Y-%m-%d %H:%M:%S} --> self.name: {self.serial}")

        # Model
        logger.info(f"{datetime.datetime.now():%Y-%m-%d %H:%M:%S} [Scanner:{self.ip}] --> Trying to get model name")
        model = root.find(".//{http://schemas.xmlsoap.org/ws/2006/02/devprof}ModelName")
        logger.info(f"{datetime.datetime.now():%Y-%m-%d %H:%M:%S} --> model: {model}")
        if model is not None:
            self.model = model.text.strip()
        logger.info(f"{datetime.datetime.now():%Y-%m-%d %H:%M:%S} --> self.name: {self.model}")

        # Manufacturer
        logger.info(f"{datetime.datetime.now():%Y-%m-%d %H:%M:%S} [Scanner:{self.ip}] --> Trying to get Manufacturer")
        mf = root.find(".//{http://schemas.xmlsoap.org/ws/2006/02/devprof}Manufacturer")
        logger.info(f"{datetime.datetime.now():%Y-%m-%d %H:%M:%S} --> mf: {mf}")
        if mf is not None:
            self.manufacturer = mf.text.strip()
        logger.info(f"{datetime.datetime.now():%Y-%m-%d %H:%M:%S} --> self.name: {self.manufacturer}")

        logger.info(f"{datetime.datetime.now():%Y-%m-%d %H:%M:%S} [Scanner:{self.ip}] Metadaten: {self.name} | FW={self.firmware} | SN={self.serial}")

    # wird aufgerufen wenn ein Scanner offline gesetzt wird
    def mark_offline(self):
        if self.online:
            logger.warning(f"[Scanner Offline] {self.ip} ({self.friendly_name or self.name})")
        self.online = False
        if not self.offline_since:
            self.offline_since = datetime.datetime.now()
            self.remove_after = self.offline_since + datetime.timedelta(seconds=self.max_age)

#SCANNERS = {}  # key = UUID oder IP

