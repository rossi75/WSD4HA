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
#from wsd import UDP_listener_3702, heartbeat_monitor, handle_scan_job
#from config import WSD_HTTP_PORT, WSD_OFFLINE_TIMEOUT, WSD_SCAN_FOLDER
#from config import OFFLINE_TIMEOUT, SCAN_FOLDER, HTTP_PORT
from config import OFFLINE_TIMEOUT, SCAN_FOLDER, HTTP_PORT, MAX_FILES
#from globals import SCANNERS, OFFLINE_TIMEOUT, SCAN_FOLDER, MAX_FILES
from globals import SCANNERS, NAMESPACES
#from globals import SCANNERS, list_scanners 
#from globals import SCANNERS, list_scanners, OFFLINE_TIMEOUT
from scanner import Scanner
#from scan_job import handle_scan_job

#NAMESPACES_NOTIFY = {
#    "s": "http://www.w3.org/2003/05/soap-envelope",
#    "wse": "http://schemas.xmlsoap.org/ws/2004/08/eventing",
#    "wscn": "http://schemas.microsoft.com/windows/2006/08/wdp/scan",  # optional
#}

logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')
logger = logging.getLogger("wsd-addon")

# ---------------- WebUI ----------------
async def status_page(request):
    logger.info(f"{datetime.datetime.now():%Y-%m-%d %H:%M:%S} [WEBSERVER:status_page] received request for status page")
    # Dateien
    files = sorted(SCAN_FOLDER.iterdir(), reverse=True)[:MAX_FILES]
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
        if delta > OFFLINE_TIMEOUT:
            s.online = False
        color = "green" if s.online else ("orange" if delta < 2*OFFLINE_TIMEOUT else "red")
#        formats = ", ".join(s.formats)
        #formats = ", ".join(s.types)
#        scanner_list += f"<tr style='color:{color}'>
        scanner_list += "<tr style='color:{color}'>"
        scanner_list += "<td>{s.ip}</td>"
        scanner_list += "<td>{s.uuid}</td>"
        scanner_list += "<td>{s.friendly_name or ''}</td>"
        scanner_list += "<td>{s.mac or ''}</td>"
        scanner_list += "<td>{'Online' if s.online else 'Offline'}</td>"
        scanner_list += "<td>{s.last_seen.strftime('%Y-%m-%d %H:%M:%S')}</td>"
        scanner_list += "<td>{s.xaddr or ''}</td>"
        scanner_list += "<td>{s.subscription_id or ''}</td>"
        scanner_list += "<td>{s.subscription_expires or ''}</td>"
        scanner_list += "<td>{s.manufacturer or ''}</td>"
        scanner_list += "<td>{s.model or ''}</td>"
        scanner_list += "<td>{s.firmware or ''}</td>"
        scanner_list += "<td>{s.serial or ''}</td>"
        scanner_list += "</tr>"

    logger.info(f"   ---> forming and delivering http-response")
    return web.Response(text=f"""
        <html>
        <head>
            <title>WSD4HA</title>
            <style>
                table {{ border-collapse: collapse; width: 100%; }}
                th, td {{ border: 1px solid #ddd; padding: 8px; }}
                th {{ background-color: #f2f2f2; }}
            </style>
        </head>
        <body>
            <h1>WSD4HA seems to be running</h1>
            <h2>Last {MAX_FILES} Scans:</h2>
            <table>
                <tr><th>Filename</th><th>Date/Time</th><th>Size (KB)</th></tr>
                {file_list}
            </table>
            <h2>Active Scanners:</h2>
            <table>
                <tr><th>IP</th><th>UUID</th><th>Name</th><th>MAC</th><th>State</th><th>Last seen</th><th>XADDR</th><th>Subscr ID</th><th>Subscr Exp</th><th>Manufacturer</th><th>Model</th><th>Firmware</th><th>Serial</th></tr>
                {scanner_list}
            </table>
        </body>
        </html>
    """, content_type="text/html")
    logger.info(f"   ---> probably delivered http-response")

#                <tr><th>Name</th><th>IP</th><th>MAC</th><th>UUID</th><th>Formats</th><th>State</th><th>Last seen</th></tr>

# ---------------- HTTP Server ----------------
async def start_http_server():
    logger.info(f"{datetime.datetime.now():%Y-%m-%d %H:%M:%S}[WEBSERVER:start_http] configuring HTTP/SOAP Server on Port {HTTP_PORT}")
    app = web.Application()
    app.router.add_get("/", status_page)
    logger.debug(f"   ---> added endpoint /")
    app.router.add_post("/wsd/notify", notify_handler)
    logger.debug(f"   ---> added endpoint /wsd/notify")
#    app.router.add_post("/wsd/scan", handle_scan_job)
#    logger.debug(f"   ---> added endpoint /wsd/scan")
    
    runner = web.AppRunner(app)
    await runner.setup()
    logger.debug(f"   ---> runner.setup().web.AppRunner(app)")
    
    # An alle Interfaces binden (0.0.0.0) -> wichtig für Docker / HA
    site = web.TCPSite(runner, "0.0.0.0", HTTP_PORT)
    await site.start()
    logger.info(f"   ---> HTTP/SOAP Server should run on Port {HTTP_PORT}")


# ---------------- NOTIFY handler ----------------
async def notify_handler(request):
    text = await request.text()
    # quick log
    logger.info(f"{datetime.datetime.now():%Y-%m-%d %H:%M:%S}[WEBSERVER:NOTIFY] received notification payload: %s", text[:600])
    try:
        root = ET.fromstring(text)
    except Exception as e:
        logger.warning("[WEBSERVER:NOTIFY] invalid xml: %s", e)
        return web.Response(status=400, text="bad xml")

    # try to extract identifier / event content
    ident = root.find(".//wse:Identifier", NAMESPACES_NOTIFY)
    body = root.find(".//s:Body", NAMESPACES_NOTIFY)
    # dump body child names for debugging
    events = []
    if body is not None:
        for child in body:
            events.append(child.tag)
    logger.info(f"WEBSERVER:[NOTIFY] identifier={ident.text if ident is not None else None}, events={events}")

    # Acknowledge (200 OK). Some implement a SOAP response; many accept simple 200.
    return web.Response(status=200, text="OK")

