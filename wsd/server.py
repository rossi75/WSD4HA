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
from globals import SCANNERS, SCAN_JOBS, NAMESPACES, STATE, USER_AGENT, LOG_LEVEL
#from scanner import Scanner
from parse import parse_notify_msg
from tools import find_scanner_by_endto_addr

logging.basicConfig(level=LOG_LEVEL, format='[%(levelname)s] %(message)s')
logger = logging.getLogger("wsd-addon")


# ---------------- HTTP Server ----------------
async def start_http_server():
    logger.info(f"[SERVER:start_http] configuring HTTP/SOAP Server on Port {HTTP_PORT}")
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

# ---------------- WebUI ----------------
async def status_page(request):
    logger.info(f"{datetime.datetime.now():%Y-%m-%d %H:%M:%S} [SERVER:status_page] received request for status page")

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
#    now = datetime.datetime.now()
    for s in SCANNERS.values():
#        delta = (now - s.last_seen).total_seconds()
#        if delta > OFFLINE_TIMEOUT:
#            s.online = False
#            s.state = False
#        color = "green" if s.online else ("orange" if delta < 2*OFFLINE_TIMEOUT else "red")
#        formats = ", ".join(s.formats)
        #formats = ", ".join(s.types)
        scanner_list = "<tr style='color:{color}'>"
        scanner_list += f"<td style='text-align:center;'>{s.friendly_name}</td>"
        scanner_list += f"<td style='text-align:center;'>{s.ip}<br>{s.mac if s.mac else ''}</td>"
        scanner_list += f"<td style='text-align:center;'>{s.state.value}<br>"
        scanner_list += f"{s.subscription_last_seen.strftime('%Y-%m-%d %H:%M:%S') if s.subscription_last_seen else ''}</td>"
        scanner_list += f"<td style='text-align:center;'>{s.first_seen.strftime('%Y-%m-%d %H:%M:%S')}<br>"
        scanner_list += f"{s.last_seen.strftime('%Y-%m-%d %H:%M:%S')}<br>"
        scanner_list += f"{s.remove_after.strftime('%Y-%m-%d %H:%M:%S') if s.remove_after else ''}</td>"
        scanner_list += f"<td style='text-align:center;'>{s.uuid}<br>"
        scanner_list += f"{s.xaddr if s.xaddr else ''}</td>"
        scanner_list += f"<td style='text-align:center;'>{s.subscription_id if s.subscription_id else ''}<br>"
        scanner_list += f"{s.end_to_addr if s.end_to_addr else ''}<br>"
        scanner_list += f"{s.destination_token if s.destination_token else ''}</td>"
        scanner_list += f"<td style='text-align:center;'>{s.manufacturer if s.manufacturer else ''}<br>"
        scanner_list += f"{s.model if s.model else ''}</td>"
        scanner_list += f"<td style='text-align:center;'>{s.firmware if s.firmware else ''}<br>"
        scanner_list += f"{s.serial if s.serial else ''}</td>"
        scanner_list += "</tr>"


    # Jobs
    job_list = ''
#    now = datetime.datetime.now()
    for j in SCAN_JOBS.values():
        job_list = "<tr style='color:{color}'>"
        job_list += f"<td style='text-align:center;'>{j.scanjob_identifier}</td>"
        job_list += f"<td style='text-align:center;'>{j.input_source}</td>"
        job_list += f"<td style='text-align:center;'>{j.scan_from_uuid}<br>"
        job_list += f"{j.xaddr}<br>"
        job_list += f"{j.subscription_identifier}<br>"
        job_list += f"{j.destination_token}</td>"
        job_list += f"<td style='text-align:center;'>{j.status.value}</td>"
        job_list += f"<td style='text-align:center;'>{j.job_created.strftime('%Y-%m-%d %H:%M:%S')}<br>"
        job_list += f"<td style='text-align:center;'>{j.remove_after.strftime('%Y-%m-%d %H:%M:%S')}</td>"
        job_list += "</tr>"
        
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
                <tr><th>Name</th><th>IP<br>[MAC]</th><th>State<br>Last Subscr</th><th>First seen<br>Last seen<br>[Remove after]</th><th>UUID<br>XADDR</th><th>Subscr ID<br>Subscr EndToAddr<br>Destination Token</th><th>Manufacturer<br>Model</th><th>Firmware<br>Serial</th></tr>
                {scanner_list}
            </table>
            <h2>List of Scans:</h2>
            <table>
                <tr><th>ScanJob ID</th><th>HW Source</th><th>Scanner UUID<br>XADDR<br>Subscr UUID<br>Destination Token</th><th>Status</th><th>Job created<br>Remove after</tr>
                {job_list}
            </table>
            <h2>Last {MAX_FILES} Scans:</h2>
            <table>
                <tr><th>Filename</th><th>Date/Time</th><th>Size (KB)</th></tr>
                {file_list}
            </table>
        </body>
        </html>
    """, content_type="text/html")

# parallel zum UI starten
# ---------------- NOTIFY Server ----------------
async def start_notify_server():
    logger.info(f"[SERVER:start_notify] configuring Notify Server on Port {NOTIFY_PORT}")

    app = web.Application()
    app.add_routes(routes)

    runner = web.AppRunner(app)
    await runner.setup()
    logger.debug(f"   ---> runner.setup().web.AppRunner(app)")

    # An alle Interfaces binden (0.0.0.0) -> wichtig für Docker / HA
    site = web.TCPSite(runner, "0.0.0.0", NOTIFY_PORT)
    await site.start()
    logger.info(f"Notify Server is running on Port {NOTIFY_PORT}")
    logger.info(f"-----------------------  Events  -------------------------")

# ---------------- NOTIFY handler ----------------
# Fängt alles hinter / ab, z.B. /6ccf7716-4dc8-47bf-aca4-5a2ae5a959ca
routes = web.RouteTableDef()
@routes.post(r'/{uuid:[0-9a-fA-F\-]+}')
async def notify_handler(request):
    logger.info(f"{datetime.datetime.now():%Y-%m-%d %H:%M:%S} [SERVER:notify_handler] received {request.method} event on {request.path}")

    scanner_uuid = ""
    EndTo_id = request.path
    scanner_uuid = find_scanner_by_endto_addr(EndTo_id)
    xml_payload = await request.text()

    if scanner_uuid is not None:
        logger.info(f"found scanner {SCANNERS[scanner_uuid].friendly_name or scanner_uuid} @ {SCANNERS[scanner_uuid].ip} for {EndTo_id}")
    else:
        logger.info(f"no search result for {EndTo_id}")
        return web.Response(status=400, text="bad notify endpoint")

    logger.debug(f"   ---> XML payload: \n {xml_payload}")

    try:
        root = ET.fromstring(xml_payload)
        asyncio.create_task(parse_notify_msg(scanner_uuid, xml_payload))      # hier wird dann der Abholauftrag an sich generiert
    except Exception as e:
        logger.warning(f"[SERVER:notify_handler] invalid xml: {e}")
        return web.Response(status=400, text="bad xml")

    return web.Response(status=202, text="Alles juut")

#
#
# --------------------------------------------------
# ---------------- END OF SERVER.PY ----------------
