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
from config import OFFLINE_TIMEOUT, SCAN_FOLDER, HTTP_PORT, MAX_FILES, NOTIFY_PORT
from globals import SCANNERS, NAMESPACES, STATE, USER_AGENT, LOG_LEVEL
from scanner import Scanner
from parse import parse_scan_available

logging.basicConfig(level=LOG_LEVEL, format='[%(levelname)s] %(message)s')
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
#        if delta > OFFLINE_TIMEOUT:
#            s.online = False
#            s.state = False
#        color = "green" if s.online else ("orange" if delta < 2*OFFLINE_TIMEOUT else "red")
#        formats = ", ".join(s.formats)
        #formats = ", ".join(s.types)
        scanner_list += "<tr style='color:{color}'>"
        scanner_list += f"<td style='text-align:center;'>{s.friendly_name}</td>"
        scanner_list += f"<td style='text-align:center;'>{s.ip}<br>{s.mac}</td>"
        scanner_list += f"<td style='text-align:center;'>{s.state.value}</td>"
        scanner_list += f"<td style='text-align:center;'>{s.first_seen.strftime('%Y-%m-%d %H:%M:%S')}<br>"
        scanner_list += f"{s.last_seen.strftime('%Y-%m-%d %H:%M:%S')}<br>"
        scanner_list += f"{s.remove_after.strftime('%Y-%m-%d %H:%M:%S') if s.remove_after else ''}</td>"
        scanner_list += f"<td style='text-align:center;'>{s.uuid}<br>"
        scanner_list += f"{s.xaddr if s.xaddr else ''}</td>"
        scanner_list += f"<td style='text-align:center;'>{s.subscription_id if s.subscription_id else ''}<br>"
        scanner_list += f"{s.end_to_addr if s.end_to_addr else ''}<br>"
        scanner_list += f"{s.subscription_last_seen.strftime('%Y-%m-%d %H:%M:%S') if s.subscription_last_seen else ''}</td>"
        scanner_list += f"<td style='text-align:center;'>{s.manufacturer if s.manufacturer else ''}<br>"
        scanner_list += f"{s.model if s.model else ''}</td>"
        scanner_list += f"<td style='text-align:center;'>{s.firmware if s.firmware else ''}<br>"
        scanner_list += f"{s.serial if s.serial else ''}</td>"
        scanner_list += "</tr>"

    logger.debug(f"   ---> probably delivered http-response")
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
            <h2>Active Scanners:</h2>
            <table>
                <tr><th>Name</th><th>IP<br>MAC</th><th>State</th><th>First seen<br>Last seen<br>Remove after</th><th>UUID<br>XADDR</th><th>Subscr ID<br>Subscr EndToAddr<br>Subscr Exp</th><th>Manufacturer<br>Model</th><th>Firmware<br>Serial</th></tr>
                {scanner_list}
            </table>
            <h2>Last {MAX_FILES} Scans:</h2>
            <table>
                <tr><th>Filename</th><th>Date/Time</th><th>Size (KB)</th></tr>
                {file_list}
            </table>
        </body>
        </html>
    """, content_type="text/html")

# ---------------- HTTP Server ----------------
async def start_http_server():
    logger.info(f"[WEBSERVER:start_http] configuring HTTP/SOAP Server on Port {HTTP_PORT}")
    app = web.Application()
    app.router.add_get("/", status_page)
    logger.debug(f"   ---> added endpoint /")
    
    runner = web.AppRunner(app)
    await runner.setup()
    logger.debug(f"   ---> runner.setup().web.AppRunner(app)")
    
    # An alle Interfaces binden (0.0.0.0) -> wichtig für Docker / HA
    site = web.TCPSite(runner, "0.0.0.0", HTTP_PORT)
    await site.start()
    logger.info(f"HTTP/SOAP Server is running on Port {HTTP_PORT}")



# ---------------- NOTIFY handler ----------------
# Fängt alles hinter / ab, z.B. /6ccf7716-4dc8-47bf-aca4-5a2ae5a959ca
routes = web.RouteTableDef()
@routes.post(r'/{uuid:[0-9a-fA-F\-]+}')
async def notify_handler(request):
    logger.info(f"{datetime.datetime.now():%Y-%m-%d %H:%M:%S} [SERVER:notify_handler] received {request.method} Event on {request.path}")

    xml_payload = await request.text()
    logger.info(f"received XML payload: \n {xml_payload}")

    try:
        root = ET.fromstring(xml_payload)
    except Exception as e:
        logger.warning(f"[SERVER:notify_handler] invalid xml: {e}")
        return web.Response(status=400, text="bad xml")

    parse_scan_available(notify_uuid, xml_payload)
    
    return web.Response(status=200, text="Alles juut")








    
    # try to extract identifier / event content
#    ident = root.find(".//wse:Identifier", NAMESPACES)
#    body = root.find(".//soap:Body", NAMESPACES)

#    if request.method == "OPTIONS":
#        logger.info(f"   --->   OPTIONS received")
#        return web.Response(status=200)   # Preflight akzeptieren
#    if request.method == "POST":
#        body = await request.text()
#        logger.info(f"   --->   POST received, SOAP:\n{body}")
#        return web.Response(text="OK")    # dump body child names for debugging
#    events = []
#    if body is not None:
#        for child in body:
#            events.append(child.tag)
#    logger.info(f"   --->   identifier={ident.text if ident is not None else None}, events={events}")

    # Acknowledge (200 OK). Some implement a SOAP response; many accept simple 200.
#    return web.Response(status=200, text="alles juut")


# ---------------- NOTIFY Server ----------------
async def start_notify_server():
    logger.info(f"[WEBSERVER:start_notify] configuring Notify Server on Port {NOTIFY_PORT}")
    # parallel zum UI starten
#from notify_server import create_notify_app

#    loop = asyncio.get_event_loop()
#    loop.create_task(web._run_app(create_notify_app(), port=5357))

    app = web.Application()
#    app.router.add_get(f"/{USER_AGENT}", notify_handler)
#    logger.debug(f"   ---> added endpoint /{USER_AGENT}")
    app.add_routes(routes)

    runner = web.AppRunner(app)
    await runner.setup()
    logger.debug(f"   ---> runner.setup().web.AppRunner(app)")

    # An alle Interfaces binden (0.0.0.0) -> wichtig für Docker / HA
    site = web.TCPSite(runner, "0.0.0.0", NOTIFY_PORT)
    await site.start()
    logger.info(f"Notify Server is running on Port {NOTIFY_PORT}")
    logger.info(f"-----------------------  Events  -------------------------")

