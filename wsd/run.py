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

# ---------------- Logging ----------------
logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')
logger = logging.getLogger("wsd-addon")

# ---------------- Optionen aus Environment ----------------
WSD_SCAN_FOLDER = Path(os.environ.get("WSD_SCAN_FOLDER", "/share/scans"))
WSD_SCAN_FOLDER.mkdir(parents=True, exist_ok=True)
#WSD_MAX_FILES = int(os.environ.get("WSD_MAX_FILES", 5))
#WSD_HTTP_PORT = int(os.environ.get("WSD_HTTP_PORT", 8080))
#WSD_OFFLINE_TIMEOUT = int(os.environ.get("WSD_OFFLINE_TIMEOUT", 300))  # Sekunden
WSD_MAX_FILES = int(os.environ.get("MAX_FILES", 5))
WSD_HTTP_PORT = int(os.environ.get("HTTP_PORT", 8080))
WSD_OFFLINE_TIMEOUT = int(os.environ.get("OFFLINE_TIMEOUT", 300))  # Sekunden

logger.info(f"Scan-Ordner: {WSD_SCAN_FOLDER}, max Dateien: {WSD_MAX_FILES}, HTTP-Port: {WSD_HTTP_PORT}, Offline Timeout: {WSD_OFFLINE_TIMEOUT}s")

# ---------------- Portprüfung ----------------
def check_port(port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.bind(('', port))
            return True
        except OSError:
            return False

if not check_port(WSD_HTTP_PORT):
    logger.error(f"[STARTUP] Port {WSD_HTTP_PORT} ist bereits belegt! Bitte anderen Port wählen.")
    sys.exit(1)

# ---------------- Scanner-Datenstruktur ----------------
class Scanner:
    def __init__(self, name, ip, mac=None, uuid=None, formats=None):
        self.name = name
        self.ip = ip
        self.mac = mac
        self.uuid = uuid
        self.formats = formats or []
        self.location = location
        self.max_age = max_age
        self.last_seen = datetime.datetime.now()
        self.online = True

    def update(self):
        self.last_seen = datetime.datetime.now()
        self.online = True
        if max_age:
            self.max_age = max_age

SCANNERS = {}  # key = UUID oder IP

# ---------------- HTTP/SOAP Server ----------------
async def handle_scan_job(request):
    logger.info("[SCAN] Scan-Job gestartet")
    data = await request.read()
    logger.info(f"[SCAN] Erste Bytes empfangen: {len(data)}")
    filename = WSD_SCAN_FOLDER / f"scan-{datetime.datetime.now():%Y%m%d-%H%M%S}.bin"
    try:
        with open(filename, "wb") as f:
            f.write(data)
        logger.info(f"[SCAN] Scan abgeschlossen: {filename} ({len(data)/1024:.1f} KB)")
    except Exception as e:
        logger.error(f"[SCAN] Fehler beim Speichern: {e}")
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
            <h1>WSD Add-on läuft</h1>
            <h2>Letzte {WSD_MAX_FILES} Scans:</h2>
            <table>
                <tr><th>Dateiname</th><th>Datum/Uhrzeit</th><th>Größe (KB)</th></tr>
                {file_list}
            </table>
            <h2>Aktive Scanner:</h2>
            <table>
                <tr><th>Name</th><th>IP</th><th>MAC</th><th>UUID</th><th>Formate</th><th>Status</th><th>Letzte Meldung</th></tr>
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
    site = web.TCPSite(runner, "0.0.0.0", WSD_HTTP_PORT)
    await site.start()
    logger.info(f"[*] HTTP SOAP Server läuft auf Port {WSD_HTTP_PORT}")

# ---------------- UDP Discovery Skeleton ----------------
async def discovery_listener():
 #   loop = asyncio.get_running_loop()

    # WSD (3702)
    MCAST_GRP = '239.255.255.250'
    MCAST_PORT = 3702

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(('', MCAST_PORT))
    mreq = socket.inet_aton(MCAST_GRP) + socket.inet_aton('0.0.0.0')
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
    logger.info("[*] UDP Discovery Listener läuft auf Port 3702")

    loop = asyncio.get_running_loop()
    while True:
        data, addr = await loop.sock_recv(sock, 1024)
        # Dummy-Daten für Scanner
        scanner_id = addr[0]  # IP als Schlüssel
        if scanner_id not in SCANNERS:
            s = Scanner(name=f"Scanner-{addr[0]}", ip=addr[0], uuid=f"UUID-{addr[0]}")
            SCANNERS[scanner_id] = s
            logger.info(f"[DISCOVERY] Neuer Scanner erkannt: {s.name} ({s.ip}) online")
        else:
            SCANNERS[scanner_id].update()
        await asyncio.sleep(0.1)

# ---------------- Scanner Heartbeat ----------------
async def heartbeat_monitor():
    while True:
        now = datetime.datetime.now()
        for s in SCANNERS.values():
            delta = (now - s.last_seen).total_seconds()
            if delta > WSD_OFFLINE_TIMEOUT and s.online:
                logger.warning(f"[DISCOVERY] Scanner {s.name} ({s.ip}) offline seit {WSD_OFFLINE_TIMEOUT} Sekunden")
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
