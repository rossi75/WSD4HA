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

# ----------------- To Do -----------------
# - max-age übernehmen
# - Drucker oder Scanner name übernehmen
# - passende antwort schreiben
# - Logs mit D/T
# - scanauftrag entgegennehmen
# - webserver zum laufen bekommen
# - nach einem neuzugang die liste anzeigen
# - nach einem abgang diesen im log ausführlich ausgeben
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
    def __init__(self, name, ip, mac=None, uuid=None, formats=None, location=None, max_age=WSD_OFFLINE_TIMEOUT):
        self.name = name
        self.ip = ip
        self.mac = mac
        self.uuid = uuid
        self.formats = formats or []
        self.location = location
        self.max_age = max_age
        self.last_seen = datetime.datetime.now()
        self.online = True

    def update(self, max_age=WSD_OFFLINE_TIMEOUT):
        self.last_seen = datetime.datetime.now()
        self.max_age = max_age
        self.online = True
#        if max_age:
#            self.max_age = max_age

SCANNERS = {}  # key = UUID oder IP

# ---------------- HTTP/SOAP Server ----------------
async def handle_scan_job(request):
    logger.info("[SCAN] Scan-Job started")
    data = await request.read()
    logger.info(f"[SCAN] Received first Bytes: {len(data)}")
    #logger.debug(f"[SCAN] Received first Bytes: {len(data)}")
    filename = WSD_SCAN_FOLDER / f"scan-{datetime.datetime.now():%Y%m%d-%H%M%S}.bin"
    try:
        with open(filename, "wb") as f:
            f.write(data)
        logger.info(f"[SCAN] Scan finished: {filename} ({len(data)/1024:.1f} KB)")
    except Exception as e:
        logger.error(f"[SCAN] Error while saving: {e}")
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
    loop = asyncio.get_running_loop()

    # WSD (3702)
    MCAST_GRP_WSD = "239.255.255.250"
    MCAST_PORT_WSD = 3702
    wsd_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    wsd_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    wsd_sock.bind(("", MCAST_PORT_WSD))
    mreq = socket.inet_aton(MCAST_GRP_WSD) + socket.inet_aton("0.0.0.0")
    wsd_sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
    logger.info("[*] WSD-Listener running on Port 3702/UDP")

    # SSDP (1900)
    MCAST_PORT_SSDP = 1900
    ssdp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    ssdp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    ssdp_sock.bind(("", MCAST_PORT_SSDP))
    ssdp_sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
    logger.info("[*] SSDP-Listener running on Port 1900/UDP")

    logger.info(f"-----------------------  Events  -------------------------")

    while True:
        # Beide Sockets überwachen
#        wsd_task = asyncio.create_task(loop.sock_recv(wsd_sock, 8192))
#        ssdp_task = asyncio.create_task(loop.sock_recv(ssdp_sock, 8192))
        wsd_task = asyncio.create_task(loop.sock_recvfrom(wsd_sock, 8192))
        ssdp_task = asyncio.create_task(loop.sock_recvfrom(ssdp_sock, 8192))

        done, pending = await asyncio.wait(
            {wsd_task, ssdp_task}, return_when=asyncio.FIRST_COMPLETED
        )

        for task in done:
            data, addr = task.result()
            ip = addr[0]

            # WSD
            if task is wsd_task:
                parsed = parse_wsd_packet(data)
                if parsed:
                    uuid = parsed.get("uuid")
                    action = parsed.get("action")
                    logger.info(f"{datetime.datetime.now():%Y%m%d %H%M%S} [WSD] from {addr} → Action={parsed['action']} UUID={parsed['uuid']}")
                    
                    key = uuid or ip
                    if key not in SCANNERS:
                        s = Scanner(name=f"Scanner_{ip}", ip=ip, uuid=uuid)
                        SCANNERS[key] = s
                        logger.info(f"{datetime.datetime.now():%Y%m%d %H%M%S} [DISCOVERY] [WSD] Neuer Scanner: {s.name} ({s.ip})")
                    else:
                        SCANNERS[key].update()
                else:
                    logger.debug(f"{datetime.datetime.now():%Y%m%d %H%M%S} [WSD] unknown packet from {addr}: {data[:80]!r}")

            # SSDP
            elif task is ssdp_task:
                headers = parse_ssdp_packet(data)
                if headers:
                    usn = headers.get("USN")
                    nt = headers.get("NT")
                    logger.info(f"{datetime.datetime.now():%Y%m%d %H%M%S} [SSDP] from {addr} → NT={headers.get('NT')} USN={headers.get('USN')}")

                    key = usn or ip
                    if key not in SCANNERS:
                        s = Scanner(name=f"Scanner_{ip}", ip=ip, uuid=usn)
                        SCANNERS[key] = s
                        logger.info(f"{datetime.datetime.now():%Y%m%d %H%M%S} [DISCOVERY] [SSDP] Neuer Scanner: {s.name} ({s.ip})")
                    else:
                        SCANNERS[key].update()
                else:
                    logger.debug(f"{datetime.datetime.now():%Y%m%d %H%M%S} [SSDP] unknown packet from {addr}: {data[:80]!r}")

        # Offene Tasks abbrechen (sonst sammeln sie sich an)
        for task in pending:
            task.cancel()

#        for task in done:
#            data, addr = task.result()
#            ip = addr[0]
#
#            if b"<wsd:Hello" in data or b"<wsd:Bye" in data:
#                # --- WSD SOAP ---
#                try:
#                    xml = ET.fromstring(data.decode(errors="ignore"))
#                    ns = {
#                        "soap": "http://www.w3.org/2003/05/soap-envelope",
#                        "wsa": "http://schemas.xmlsoap.org/ws/2004/08/addressing",
#                        "wsd": "http://schemas.xmlsoap.org/ws/2005/04/discovery",
#                    }
#                    addr_elem = xml.find(".//wsa:Address", ns)
#                    types_elem = xml.find(".//wsd:Types", ns)
#                    xaddrs_elem = xml.find(".//wsd:XAddrs", ns)
# 
#                    uuid = addr_elem.text.strip() if addr_elem is not None else None
#                    types = types_elem.text.strip().split() if types_elem is not None else []
#                    xaddrs = xaddrs_elem.text.strip().split() if xaddrs_elem is not None else []###
#
#                    if uuid:
#                        if uuid not in SCANNERS:
#                            s = Scanner(name=f"Scanner-{ip}", ip=ip, uuid=uuid, types=types, location=xaddrs[0] if xaddrs else None)
#                            SCANNERS[uuid] = s
#                            logger.info(f"[WSD] new Scanner detected: {s.name} ({s.ip}) UUID={s.uuid}")
#                        else:
#                            SCANNERS[uuid].update()
#                except Exception as e:
#                    logger.warning(f"[WSD] Error while parsing: {e}")#
#
#            elif b"NOTIFY * HTTP/1.1" in data:
#                # --- SSDP ---
#                text = data.decode(errors="ignore")
#                uuid_match = re.search(r"uuid:([a-fA-F0-9\-]+)", text)
#                location_match = re.search(r"LOCATION:\s*(.*)", text, re.IGNORECASE)
#                maxage_match = re.search(r"max-age=(\d+)", text, re.IGNORECASE)#

#                uuid = f"uuid:{uuid_match.group(1)}" if uuid_match else None
#                location = location_match.group(1).strip() if location_match else None
#                max_age = int(maxage_match.group(1)) if maxage_match else 60#
#
#                if uuid:
#                    if uuid not in SCANNERS:
#                        s = Scanner(name=f"Scanner-{ip}", ip=ip, uuid=uuid, location=location, max_age=max_age)
#                        SCANNERS[uuid] = s
#                        logger.info(f"[SSDP] new Scanner detected: {s.name} ({s.ip}) UUID={s.uuid} location={location}")
#                    else:
#                        SCANNERS[uuid].update(max_age=max_age)

    
#    while True:
#        data, addr = await loop.sock_recv(sock, 1024)
#        # Dummy-Daten für Scanner
#        scanner_id = addr[0]  # IP als Schlüssel
#        if scanner_id not in SCANNERS:
#            s = Scanner(name=f"Scanner-{addr[0]}", ip=addr[0], uuid=f"UUID-{addr[0]}")
#            SCANNERS[scanner_id] = s
#            logger.info(f"[DISCOVERY] Neuer Scanner erkannt: {s.name} ({s.ip}) online")
#        else:
#            SCANNERS[scanner_id].update()
#        await asyncio.sleep(0.1)

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
