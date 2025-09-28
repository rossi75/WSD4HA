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
from globals import SCANNERS, NAMESPACES, STATE, USER_AGENT
from scanner import Scanner

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
#        if delta > OFFLINE_TIMEOUT:
#            s.online = False
#            s.state = False
#        color = "green" if s.online else ("orange" if delta < 2*OFFLINE_TIMEOUT else "red")
#        formats = ", ".join(s.formats)
        #formats = ", ".join(s.types)
#        scanner_list += f"<tr style='color:{color}'>
        scanner_list += "<tr style='color:{color}'>"
        scanner_list += "<td>" + str(s.friendly_name or '') + "</td>"
        scanner_list += "<td>" + str(s.ip) + "</td>"
        scanner_list += "<td>" + str(s.mac or '') + "</td>"
        scanner_list += "<td>" + str(s.state.value) + "</td>"
        scanner_list += "<td>" + str(s.uuid) + "</td>"
#        scanner_list += "<td>" + str(s.last_seen.strftime('%Y-%m-%d %H:%M:%S')) + "</td>"
        scanner_list += "<td>" + str(s.first_seen.strftime('%Y-%m-%d %H:%M:%S')) + "<br>"
        scanner_list += "<td>" + str(s.last_seen.strftime('%Y-%m-%d %H:%M:%S')) + "<br>"
        scanner_list += "<td>" + str(s.subscription_last_seen.strftime('%Y-%m-%d %H:%M:%S') or '') + "<br>"
        scanner_list += "<td>" + str(s.remove_after.strftime('%Y-%m-%d %H:%M:%S') or '') + "</td>"
        scanner_list += "<td>" + str(s.xaddr or '') + "</td>"
        scanner_list += "<td>" + str(s.subscription_id or '') + "<br>"
        scanner_list += "<td>" + str(s.subscription_expires or '') + "</td>"
        scanner_list += "<td>" + str(s.manufacturer or '') + "<br>"
        scanner_list += "<td>" + str(s.model or '') + "</td>"
        scanner_list += "<td>" + str(s.firmware or '') + "<br>"
        scanner_list += "<td>" + str(s.serial or '') + "</td>"
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
                <tr><th>Name</th><th>IP</th><th>MAC</th><th>State</th><th>UUID</th><th>First seen<br>Last seen<br>Last Subscription<br>Remove after</th><th>XADDR</th><th>Subscr ID</th><th>Subscr Exp</th><th>Manufacturer<br><th>Model</th><th>Firmware<br><th>Serial</th></tr>
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
#    app.router.add_post("/wsd/notify", notify_handler)
#    logger.debug(f"   ---> added endpoint /wsd/notify")
#    app.router.add_post("/wsd/scan", handle_scan_job)
#    logger.debug(f"   ---> added endpoint /wsd/scan")
    
    runner = web.AppRunner(app)
    await runner.setup()
    logger.debug(f"   ---> runner.setup().web.AppRunner(app)")
    
    # An alle Interfaces binden (0.0.0.0) -> wichtig für Docker / HA
    site = web.TCPSite(runner, "0.0.0.0", HTTP_PORT)
    await site.start()
    logger.info(f"HTTP/SOAP Server is running on Port {HTTP_PORT}")

# ---------------- NOTIFY handler ----------------
#@routes.post('/WSDAPI')      # 👈 Decorator kommt direkt vor die Funktion
routes = web.RouteTableDef()
@routes.route('*', '/WSDAPI')
async def notify_handler(request):
    logger.info(f"{datetime.datetime.now():%Y-%m-%d %H:%M:%S} [WEBSERVER:NOTIFY] received {request.method} on {request.path}")

    text = await request.text()
    logger.debug(f"payload: \n {text[:600]}")

    try:
        root = ET.fromstring(text)
    except Exception as e:
        logger.warning("[WEBSERVER:NOTIFY] invalid xml: %s", e)
        return web.Response(status=400, text="bad xml")

    # try to extract identifier / event content
    ident = root.find(".//wse:Identifier", NAMESPACES)
    body = root.find(".//s:Body", NAMESPACES)
    
    # dump body child names for debugging
    events = []
    if body is not None:
        for child in body:
            events.append(child.tag)
    logger.info(f"WEBSERVER:[NOTIFY] identifier={ident.text if ident is not None else None}, events={events}")

    # Acknowledge (200 OK). Some implement a SOAP response; many accept simple 200.
    return web.Response(status=200, text="alles juut")


# ---------------- NOTIFY Server ----------------
async def start_notify_server():
    logger.info(f"[WEBSERVER:start_notify] configuring Notify Server on Port {NOTIFY_PORT}")
    # parallel zum UI starten
#from notify_server import create_notify_app

#    loop = asyncio.get_event_loop()
#    loop.create_task(web._run_app(create_notify_app(), port=5357))

    app = web.Application()
    app.router.add_get(f"/{USER_AGENT}", notify_handler)
    logger.debug(f"   ---> added endpoint /{USER_AGENT}")

    runner = web.AppRunner(app)
    await runner.setup()
    logger.debug(f"   ---> runner.setup().web.AppRunner(app)")

    # An alle Interfaces binden (0.0.0.0) -> wichtig für Docker / HA
    site = web.TCPSite(runner, "0.0.0.0", NOTIFY_PORT)
    await site.start()
    logger.info(f"Notify Server is running on Port {NOTIFY_PORT}")
    logger.info(f"-----------------------  Events  -------------------------")

