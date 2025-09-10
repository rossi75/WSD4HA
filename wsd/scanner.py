from config import WSD_OFFLINE_TIMEOUT
#from config import WSD_HTTP_PORT, WSD_OFFLINE_TIMEOUT, WSD_SCAN_FOLDER

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
        if self.xaddr:
            try:
                self.fetch_metadata()
            except Exception as e:
                logger.warning(f"[Scanner:{self.ip}] Konnte Metadaten nicht abrufen: {e}")

    def update(self, max_age=WSD_OFFLINE_TIMEOUT):
        self.last_seen = datetime.datetime.now()
        self.max_age = max_age
        self.online = True
        self.offline_since = None
        self.remove_after = None

    def fetch_metadata(self):
        logger.info(f"[META]] trying to request Metadata from {self.ip} {e}")
        # Fragt Scanner-Metadaten per WS-Transfer/Get ab

        if not self.xaddr:
            logger.warning(f"[META]] missing .xaddr element !")
            return

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

        logger.debug(f"{datetime.datetime.now():%Y%m%d %H%M%S} [Scanner:{self.ip}] Sende Metadata-Request an {self.xaddr}")
        r = httpx.post(self.xaddr, data=soap_request, headers=headers, timeout=5.0)

        if r.status_code != 200:
            raise RuntimeError(f"HTTP {r.status_code} von {self.xaddr}")

        root = ET.fromstring(r.text)

        # FriendlyName
        fn = root.find(".//{http://schemas.xmlsoap.org/ws/2006/02/devprof}FriendlyName")
        if fn is not None and fn.text:
            self.name = fn.text.strip()

        # FirmwareVersion
        fw = root.find(".//{http://schemas.xmlsoap.org/ws/2006/02/devprof}FirmwareVersion")
        if fw is not None:
            self.firmware = fw.text.strip()

        # SerialNumber
        sn = root.find(".//{http://schemas.xmlsoap.org/ws/2006/02/devprof}SerialNumber")
        if sn is not None:
            self.serial = sn.text.strip()

        # Model
        model = root.find(".//{http://schemas.xmlsoap.org/ws/2006/02/devprof}ModelName")
        if model is not None:
            self.model = model.text.strip()

        # Manufacturer
        mf = root.find(".//{http://schemas.xmlsoap.org/ws/2006/02/devprof}Manufacturer")
        if mf is not None:
            self.manufacturer = mf.text.strip()

        logger.info(f"{datetime.datetime.now():%Y%m%d %H%M%S} [Scanner:{self.ip}] Metadaten: {self.name} | FW={self.firmware} | SN={self.serial}")

    # wird aufgerufen wenn ein Scanner offline gesetzt wird
    def mark_offline(self):
        if self.online:
            logger.warning(f"[Scanner Offline] {self.ip} ({self.friendly_name or self.name})")
        self.online = False
        if not self.offline_since:
            self.offline_since = datetime.datetime.now()
            self.remove_after = self.offline_since + datetime.timedelta(seconds=self.max_age)

SCANNERS = {}  # key = UUID oder IP

