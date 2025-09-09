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
# - neuer scanner wird zu oft erkannt

# ---------------- Logging ----------------
logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')
logger = logging.getLogger("wsd-addon")

# ---------------- Optionen aus Environment ----------------
#WSD_SCAN_FOLDER = Path(os.environ.get("WSD_SCAN_FOLDER", "/share/scans"))
WSD_SCAN_FOLDER = Path(os.environ.get("SCAN_FOLDER", "/share/scans"))
WSD_SCAN_FOLDER.mkdir(parents=True, exist_ok=True)
#WSD_MAX_FILES = int(os.environ.get("WSD_MAX_FILES", 5))
#WSD_HTTP_PORT = int(os.environ.get("WSD_HTTP_PORT", 8080))
#WSD_OFFLINE_TIMEOUT = int(os.environ.get("WSD_OFFLINE_TIMEOUT", 300))  # Sekunden
#WSD_HTTP_PORT = int(os.environ.get("HTTP_PORT", 8080))
WSD_HTTP_PORT = 8110
WSD_MAX_FILES = int(os.environ.get("MAX_FILES", 5))
WSD_OFFLINE_TIMEOUT = int(os.environ.get("OFFLINE_TIMEOUT", 300))  # Sekunden
#LOCAL_IP = get_local_ip()

logger.info(f"**********************************************************")
logger.info(f"Starting up WSD Scanner Service at {datetime.datetime.now():%d.%m.%Y, %H:%M:%S}")
logger.info(f"---------------------  Configuration  ---------------------")
logger.info(f"Scan-Path: {WSD_SCAN_FOLDER}")
logger.info(f"max scanned files to show: {WSD_MAX_FILES}")
logger.info(f"HTTP-Port for UI: {WSD_HTTP_PORT}")
logger.info(f"Offline Timeout: {WSD_OFFLINE_TIMEOUT}s")

# ---------------- lokale IP abfragen ----------------
def get_host_ip():
    try:
        # Liest die IP der Standard-Route (funktioniert auch in Docker)
        result = subprocess.check_output("ip route get 1.1.1.1 | awk '{print $7}'", shell=True)
        return result.decode().strip()
    except Exception as e:
        logger.warning(f"{datetime.datetime.now():%Y%m%d %H%M%S} [*] Could not obtain Host IP: {e}")
        return "127.0.0.1"

def get_local_ip():
    try:
        # UDP-Socket zu einer externen Adresse öffnen (wird nicht gesendet)
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))  # Google DNS, nur für Routing
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        logger.warning(f"{datetime.datetime.now():%Y%m%d %H%M%S} [*] Could not obtain Host IP: {e}")
        return "undefined"

#LOCAL_IP = get_local_ip()
LOCAL_IP = get_host_ip()

# ---------------- Portprüfung ----------------
def check_port(port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.bind(('', port))
            return True
        except OSError:
            return False

if not check_port(WSD_HTTP_PORT):
    logger.error(f"[*] Port {WSD_HTTP_PORT} is already in use!")
    sys.exit(1)
else:
    logger.info(f"Statusserver reachable at {LOCAL_IP}:{WSD_HTTP_PORT}")

# ---------------- Scanner-Datenstruktur ----------------
class Scanner:
    def __init__(self, name, ip, mac=None, uuid=None, formats=None, location=None, max_age=WSD_OFFLINE_TIMEOUT, xaddr=""):
        self.name = name
        self.ip = ip
        self.mac = mac
        self.uuid = uuid
        self.formats = formats or []
        self.location = location
        self.max_age = max_age
        self.xaddr = xaddr            # Service-Adresse (aus <wsd:XAddrs>)
        self.last_seen = datetime.datetime.now()
        self.online = True
        self.firmware = None
        self.serial = None
        self.model = None
        self.manufacturer = None

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
#        if max_age:
#            self.max_age = max_age

    def fetch_metadata(self):
        """Fragt Scanner-Metadaten per WS-Transfer/Get ab"""
        if not self.xaddr:
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

SCANNERS = {}  # key = UUID oder IP

# ---------------- HTTP/SOAP Server ----------------
async def handle_scan_job(request):
    logger.info("{datetime.datetime.now():%Y%m%d %H%M%S} [SCAN] Scan-Job started")
    data = await request.read()
    logger.info(f"{datetime.datetime.now():%Y%m%d %H%M%S} [SCAN] Received first Bytes: {len(data)}")
    #logger.debug(f"[SCAN] Received first Bytes: {len(data)}")
    filename = WSD_SCAN_FOLDER / f"scan-{datetime.datetime.now():%Y%m%d-%H%M%S}.bin"
    try:
        with open(filename, "wb") as f:
            f.write(data)
        logger.info(f"{datetime.datetime.now():%Y%m%d %H%M%S} [SCAN] Scan finished: {filename} ({len(data)/1024:.1f} KB)")
    except Exception as e:
        logger.error(f"{datetime.datetime.now():%Y%m%d %H%M%S} [SCAN] Error while saving: {e}")
    return web.Response(text="""
        <soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope">
            <soap:Body>
                <ScanJobResponse>OK</ScanJobResponse>
            </soap:Body>
        </soap:Envelope>
    """, content_type='application/soap+xml')

# ---------------- WebUI ----------------
async def status_page(request):
    # Dateien
    files = sorted(WSD_SCAN_FOLDER.iterdir(), reverse=True)[:WSD_MAX_FILES]
    file_list = ''
    for f in files:
        stat = f.stat()
        timestamp = datetime.datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M:%S")
        size_kb = stat.st_size / 1024
        file_list += f"<tr><td>{f.name}</td><td>{timestamp}</td><td>{size_kb:.1f} KB</td></tr>"

    # Scanner
    scanner_list = ''
    now = datetime.datetime.now()
    for s in SCANNERS.values():
        delta = (now - s.last_seen).total_seconds()
        if delta > WSD_OFFLINE_TIMEOUT:
            s.online = False
        color = "green" if s.online else ("orange" if delta < 2*WSD_OFFLINE_TIMEOUT else "red")
        formats = ", ".join(s.formats)
        #formats = ", ".join(s.types)
        scanner_list += f"<tr style='color:{color}'><td>{s.name}</td><td>{s.ip}</td><td>{s.mac or ''}</td><td>{s.uuid or ''}</td><td>{formats}</td><td>{'Online' if s.online else 'Offline'}</td><td>{s.last_seen.strftime('%Y-%m-%d %H:%M:%S')}</td></tr>"

    return web.Response(text=f"""
        <html>
        <head>
            <title>WSD Add-on Status</title>
            <style>
                table {{ border-collapse: collapse; width: 100%; }}
                th, td {{ border: 1px solid #ddd; padding: 8px; }}
                th {{ background-color: #f2f2f2; }}
            </style>
        </head>
        <body>
            <h1>WSD Add-on running</h1>
            <h2>Last {WSD_MAX_FILES} Scans:</h2>
            <table>
                <tr><th>Filename</th><th>Date/Time</th><th>Size (KB)</th></tr>
                {file_list}
            </table>
            <h2>Active Scanners:</h2>
            <table>
                <tr><th>Name</th><th>IP</th><th>MAC</th><th>UUID</th><th>Formats</th><th>State</th><th>Last seen</th></tr>
                {scanner_list}
            </table>
        </body>
        </html>
    """, content_type="text/html")

async def start_http_server():
    app = web.Application()
    app.router.add_post("/wsd/scan", handle_scan_job)
    app.router.add_get("/", status_page)
    
    runner = web.AppRunner(app)
    await runner.setup()
    
    # An alle Interfaces binden (0.0.0.0) -> wichtig für Docker / HA
    site = web.TCPSite(runner, "0.0.0.0", WSD_HTTP_PORT)
    await site.start()
    logger.info(f"[*] HTTP SOAP Server running on Port {WSD_HTTP_PORT}")

# ---------------- WSD SOAP Parser ----------------
def parse_wsd_packet(data: bytes):
    try:
        xml = ET.fromstring(data.decode("utf-8", errors="ignore"))
        action = xml.find(".//{http://schemas.xmlsoap.org/ws/2004/08/addressing}Action")
        uuid = xml.find(".//{http://schemas.xmlsoap.org/ws/2004/08/addressing}Address")
        return {
            "action": action.text if action is not None else None,
            "uuid": uuid.text if uuid is not None else None,
        }
    except Exception as e:
        logger.debug(f"{datetime.datetime.now():%Y%m%d %H%M%S} [WSD] Error while parsing: {e}")
        return None

# ---------------- SSDP Parser ----------------
def parse_ssdp_packet(data: bytes):
    try:
        text = data.decode("utf-8", errors="ignore")
        lines = text.split("\r\n")
        headers = {}
        for line in lines[1:]:  # Erste Zeile ist z.B. NOTIFY * HTTP/1.1
            if ":" in line:
                k, v = line.split(":", 1)
                headers[k.strip().upper()] = v.strip()
        return headers
    except Exception as e:
        logger.debug(f"{datetime.datetime.now():%Y%m%d %H%M%S} [SSDP] Error while parsing: {e}")
        return None

# ---------------- UDP Discovery Skeleton ----------------
async def discovery_listener():
#    loop = asyncio.get_running_loop()

    # WSD (3702)
    MCAST_GRP = "239.255.255.250"
    MCAST_PORT = 3702
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("", MCAST_PORT))
    mreq = socket.inet_aton(MCAST_GRP) + socket.inet_aton("0.0.0.0")
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
    logger.info("[*] WSD-Listener running on Port 3702/UDP")

    logger.info(f"-----------------------  Events  -------------------------")

    loop = asyncio.get_running_loop()
    while True:
        data, addr = await loop.sock_recvfrom(sock, 8192)
        ip = addr[0]
        
        try:
            root = ET.fromstring(data.decode("utf-8", errors="ignore"))
        except Exception:
            continue

        #action = root.find(".//{http://schemas.xmlsoap.org/ws/2004/08/addressing}Action")
        #if action is None:
        #    continue
        #action_text = action.text.strip()
        action_elem = root.find(".//wsa:Action", NAMESPACES)
        action_text = None
        if action_elem is not None and action_elem.text:
            action_text = action_elem.text.split("/")[-1]  # → "Hello|Bye|Probe"
    
        #types = root.find(".//{http://schemas.xmlsoap.org/ws/2005/04/discovery}Types")
        #types_text = types.text.strip() if types.text else ""
#        types_elem = root.find(".//{http://schemas.xmlsoap.org/ws/2005/04/discovery}Types")
#        if types_elem is not None and types_elem.text:
#            types_text = types_elem.text.strip()
        types_elem = root.find(".//wsd:Types", NAMESPACES)
        types_text = ""
        if types_elem is not None and types_elem.text:
            # Zerlegen + Präfixe entfernen
            types_text = " ".join(t.split(":")[-1] for t in types_elem.text.split())

#        uuid_elem = root.find(".//{http://schemas.xmlsoap.org/ws/2004/08/addressing}Address")
#        if uuid_elem is not None
#            uuid = uuid_elem.text.strip()
#        else f"UUID-{ip}"

        # UUID (ohne urn:uuid:)
        uuid_elem = root.find(".//wsa:Address", NAMESPACES)
        uuid_clean = None
        if uuid_elem is not None and uuid_elem.text:
            uuid_text = uuid_elem.text.strip()
            if uuid_text.startswith("urn:uuid:"):
                uuid_clean = uuid_text.replace("urn:uuid:", "")
            else:
                uuid_clean = uuid_text
        
        logger.info(f"{datetime.datetime.now():%Y%m%d %H%M%S} [DISCOVERY] received from {ip} ({uuid}), Action={action_text}, Types={types_text}")

        # Nur Scanner beachten
        #if types is None or "wscn:ScanDeviceType" not in types.text:
        if "wscn:ScanDeviceType" not in types_text:
            continue

        if "Hello" in action_text:
            uuid = root.find(".//{http://schemas.xmlsoap.org/ws/2004/08/addressing}Address")
            uuid = uuid.text.strip() if uuid is not None else f"UUID-{ip}"
            if uuid not in SCANNERS:
                SCANNERS[uuid] = Scanner(name=f"Scanner-{ip}", ip=ip, uuid=uuid)
                logger.info(f"{datetime.datetime.now():%Y%m%d %H%M%S} [HELLO] New Scanner: {SCANNERS[uuid].name} ({ip})")
            else:
                SCANNERS[uuid].update()
                logger.info(f"{datetime.datetime.now():%Y%m%d %H%M%S} [HELLO]known Scanner back again: {SCANNERS[uuid].name} ({ip})")
        
        elif "Bye" in action_text:
            uuid = root.find(".//{http://schemas.xmlsoap.org/ws/2004/08/addressing}Address")
            uuid = uuid.text.strip() if uuid is not None else f"UUID-{ip}"
            if uuid in SCANNERS:
                logger.info(f"{datetime.datetime.now():%Y%m%d %H%M%S} [BYE] Scanner offline: {SCANNERS[uuid].name} ({ip})")
                del SCANNERS[uuid]

        # Nach jedem Update: Liste loggen
        logger.info("[SCANNERS] registered Scanners:")
#        for s in SCANNERS.values():
#            logger.info(f"  - {s.name} ({s.ip}, {s.uuid})")
        for idx, s in enumerate(SCANNERS.values(), start=1):
            logger.info(f"[{idx}] {s.name} ({s.ip}) UUID={s.uuid} Online={s.online}")

        # Offene Tasks abbrechen (sonst sammeln sie sich an)
    #    for task in pending:
    #        task.cancel()

#                    logger.info(f"{datetime.datetime.now():%Y%m%d %H%M%S} [WSD] from {addr} → Action={parsed['action']} UUID={parsed['uuid']}")
#                        logger.info(f"{datetime.datetime.now():%Y%m%d %H%M%S} [DISCOVERY] [WSD] Neuer Scanner: {s.name} ({s.ip})")
#                    logger.debug(f"{datetime.datetime.now():%Y%m%d %H%M%S} [WSD] unknown packet from {addr}: {data[:80]!r}")
#                   logger.info(f"{datetime.datetime.now():%Y%m%d %H%M%S} [SSDP] from {addr} → NT={headers.get('NT')} USN={headers.get('USN')}")
#                        logger.info(f"{datetime.datetime.now():%Y%m%d %H%M%S} [DISCOVERY] [SSDP] Neuer Scanner: {s.name} ({s.ip})")
#                    logger.debug(f"{datetime.datetime.now():%Y%m%d %H%M%S} [SSDP] unknown packet from {addr}: {data[:80]!r}")
#                            logger.info(f"[WSD] new Scanner detected: {s.name} ({s.ip}) UUID={s.uuid}")
#                    logger.warning(f"[WSD] Error while parsing: {e}")#
#                        logger.info(f"[SSDP] new Scanner detected: {s.name} ({s.ip}) UUID={s.uuid} location={location}")
#                        SCANNERS[uuid].update(max_age=max_age)
#            logger.info(f"[DISCOVERY] Neuer Scanner erkannt: {s.name} ({s.ip}) online")

# ---------------- Scanner Heartbeat ----------------
async def heartbeat_monitor():
    while True:
        now = datetime.datetime.now()
        for s in SCANNERS.values():
            delta = (now - s.last_seen).total_seconds()
            if delta > WSD_OFFLINE_TIMEOUT and s.online:
                s.online = false
                logger.warning(f"{datetime.datetime.now():%Y%m%d %H%M%S} [DISCOVERY] Scanner {s.name} ({s.ip}) offline since {WSD_OFFLINE_TIMEOUT} Seconds")
        await asyncio.sleep(5)

# ---------------- Main ----------------
async def main():
    await asyncio.gather(
        start_http_server(),
        discovery_listener(),
        heartbeat_monitor()
    )

if __name__ == "__main__":
    asyncio.run(main())
