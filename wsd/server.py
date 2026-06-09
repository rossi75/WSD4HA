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
from globals import SCANNERS, SCAN_JOBS, NAMESPACES, STATE, USER_AGENT, logger
from parse import parse_notify_msg
from tools import find_scanner_by_endto_addr
from scan_job import run_scan_job


# ---------------- Download a scanned file ----------------
# http://homeassistant:8110/download/file.jpg
async def download_file(request):
    filename = os.path.basename(request.match_info["filename"])
    filepath = os.path.join(SCAN_FOLDER, filename)
    logger.info(f"received download request for {filename}, which is at {filepath}")

    if not os.path.isfile(filepath):
        raise web.HTTPNotFound(text="File not found")
#        return "File not found", 404

    return web.FileResponse(path=filepath, headers={"Content-Disposition": f'attachment; filename="{filename}"'})

# ---------------- delete a scanned file ----------------
# http://homeassistant:8110/delete/file.jpg
async def delete_file(request):
    filename = os.path.basename(request.match_info["filename"])
    filepath = os.path.join(SCAN_FOLDER, filename)
    logger.info(f"received request for delete {filename}, which is at {filepath}")

    if not os.path.isfile(filepath):
        raise web.HTTPNotFound(text="File not found")

    try:
        os.remove(filepath)
    except Exception as e:
        raise web.HTTPInternalServerError(text=str(e))
    raise web.HTTPFound("/")

# ---------------- pin a Scanner to File ----------------
# http://homeassistant:8110/pin/{uuid}
async def pin_scanner_handler(request):
    uuid = request.match_info["uuid"]
    logger.info(f"received pinning request for {uuid}")
    SCANNERS[uuid].pin_scanner()
    raise web.HTTPFound("/")

# ---------------- unpin a Scanner from File ----------------
# http://homeassistant:8110/unpin/{uuid}
async def unpin_scanner_handler(request):
    uuid = request.match_info["uuid"]
    logger.info(f"received unpinning request for {uuid}")
    SCANNERS[uuid].unpin_scanner()
    await asyncio.sleep(2)
    raise web.HTTPFound("/")

# ---------------- HTTP Server ----------------
async def start_http_server():
    logger.info(f"[SERVER:start_http] configuring HTTP Server for UI on Port {HTTP_PORT}")
    app = web.Application()
    app.router.add_get("/", status_page)
    logger.info("   ---> added endpoint /")
    app.router.add_get("/download/{filename}", download_file)
    logger.info("   ---> added endpoint /download/{filename}")
    app.router.add_get("/delete/{filename}", delete_file)
    logger.info("   ---> added endpoint /delete/{filename}")
    app.router.add_get("/pin/{uuid}", pin_scanner_handler)
    logger.info("   ---> added endpoint /pin/{uuid}")
    app.router.add_get("/unpin/{uuid}", unpin_scanner_handler)
    logger.info("   ---> added endpoint /unpin/{uuid}")
    
    runner = web.AppRunner(app)
    await runner.setup()
    logger.debug(f"   ---> runner.setup().web.AppRunner(app)")
    
    # An alle Interfaces binden (0.0.0.0) -> wichtig für Docker / HA
    site = web.TCPSite(runner, "0.0.0.0", HTTP_PORT)
    await site.start()
    logger.info(f"HTTP Server for UI is running on Port {HTTP_PORT}")

# ---------------- WebUI ----------------
async def status_page(request):
    logger.info(f"{datetime.datetime.now():%Y-%m-%d %H:%M:%S} [SERVER:status_page] received request for status page")

    # Scanner
    scanner_list = ''
    for s in SCANNERS.values():
        if s.pinned:
            pin_button = (
                f"Pinned<br>"
                f"<button "
                f"title=\"Unpin Scanner\" "
                f"onclick=\"window.location.href='/unpin/{s.uuid}'\">"
                f"📌"
                f"</button>"
            )
        else:
            pin_button = (
                f"Unpinned<br>"
                f"<button "
                f"title=\"Pin Scanner\" "
                f"onclick=\"window.location.href='/pin/{s.uuid}'\">"
                f"📍"
                f"</button>"
            )
#    if s.pinned:
#            pin_button = f'<a href="/unpin/{s.uuid}">-</a>'
#            pin_button = f'<a href="/unpin/{s.uuid}">unpin</a>'
#        else:
#            pin_button = f'<a href="/pin/{s.uuid}">+</a>'
#            pin_button = f'<a href="/pin/{s.uuid}">pin</a>'
        scanner_list = "<tr style='color:{color}'>"
        scanner_list += (f"<td style='text-align:center;'>{pin_button}</td>")
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
    for j in SCAN_JOBS.values():
        job_list = "<tr style='color:{color}'>"
        job_list += f"<td style='text-align:center;'>{j.scanjob_identifier}</td>"
        job_list += f"<td style='text-align:center;'>{j.input_source}</td>"
        job_list += f"<td style='text-align:center;'>{j.scan_from_uuid}<br>"
        job_list += f"{j.xaddr}<br>"
        job_list += f"{j.subscription_identifier}<br>"
        job_list += f"{j.destination_token}</td>"
        job_list += f"<td style='text-align:center;'>{j.job_id}<br>"
        job_list += f"{j.job_token}</td>"
        job_list += f"<td style='text-align:center;'>{j.state.value}</td>"
        job_list += f"<td style='text-align:center;'>{j.job_created.strftime('%Y-%m-%d %H:%M:%S')}<br>"
        job_list += f"{j.remove_after.strftime('%Y-%m-%d %H:%M:%S')}</td>"
        job_list += "</tr>"

    # Dateien
    files = sorted(SCAN_FOLDER.iterdir(), key=lambda f: f.stat().st_mtime, reverse=True)[:MAX_FILES]
    file_list = ''
    logger.info(f"files from {SCAN_FOLDER}:")
    for f in files:
        stat = f.stat()
        timestamp = datetime.datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M:%S")
        size_kb = stat.st_size / 1024
        filepath = f"{SCAN_FOLDER}/{f.name}"
        logger.info(f"{timestamp}, {size_kb:.1f} kB, {filepath}")
#            f"<td>{f.name}</td>"
        file_list += (
            f"<tr>"
            f"<td><a href='/download/{f.name}'>{f.name}</a></td>"
            f"<td style='text-align:center;'>{timestamp}</td>"
            f"<td style='text-align:center;'>{size_kb:.1f} kB</td>"
            f"<td style='text-align:center;'>"
            f"<button title=\"Download\"onclick=\"window.location.href='/download/{f.name}'\">⬇</button>"
            f"&nbsp;"
            f"<button title=\"Delete\" onclick=\"confirmDelete('{f.name}')\">🗑</button>"
            f"</td>"
            f"</tr>"
        )

    logger.debug(f"   ---> probably delivering http-response")
    return web.Response(text=f"""
        <html>
        <head>
            <title>WSD4HA</title>
            <meta http-equiv="refresh" content="60">
            <style>
                table {{ border-collapse: collapse; width: 100%; }}
                th, td {{ border: 1px solid #ddd; padding: 8px; }}
                th {{ background-color: #f2f2f2; }}
            </style>
            <script>
            function confirmDelete(filename) {{
                if (confirm("Delete file '" + filename + "' ?")) {{
                    window.location.href = "/delete/" + filename;
                }}
            }}
            </script>
        </head>
        <body>
            <h1>WSD4HA seems to be running</h1>
            <h2>Active Scanners:</h2>
            <table>
                <tr><th>Pin</th><th>Name</th><th>IP<br>[MAC]</th><th>State<br>Last Subscr</th><th>First seen<br>Last seen<br>[Remove after]</th><th>UUID<br>XADDR</th><th>Subscr ID<br>Subscr EndToAddr<br>Destination Token</th><th>Manufacturer<br>Model</th><th>Firmware<br>Serial</th></tr>
                {scanner_list}
            </table>
            <h2>List of Scans:</h2>
            <table>
                <tr><th>ScanJob ID</th><th>HW Source</th><th>Scanner UUID<br>XADDR<br>Subscr UUID<br>Destination Token</th><th>Job ID<br>Job Token</th><th>Status</th><th>Job created<br>Remove after</tr>
                {job_list}
            </table>
            <h2>Last {MAX_FILES} Scans:</h2>
            <table>
                <tr><th>Filename</th><th>Date/Time</th><th>Size (kB)</th><th>File Operation</th></tr>
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
    logger.info(f"***************************************************************************************************************")
    logger.info(f"*                                                E V E N T S                                                  *")
    logger.info(f"***************************************************************************************************************")
# ---------------- NOTIFY handler ----------------
# Fängt alles hinter / ab, z.B. /6ccf7716-4dc8-47bf-aca4-5a2ae5a959ca
routes = web.RouteTableDef()
@routes.post(r'/{uuid:[0-9a-fA-F\-]+}')
async def notify_handler(request):
    logger.info(f"{datetime.datetime.now():%Y-%m-%d %H:%M:%S} [SERVER:notify_handler] received {request.method} event on {request.path}")
    xml_payload = await request.text()
    logger.debug(f"   ---> XML payload: \n {xml_payload}")

    scanner_uuid = ""
    EndTo_id = request.path
    scanner_uuid = find_scanner_by_endto_addr(EndTo_id)

    if scanner_uuid is not None:
        logger.info(f"found scanner {SCANNERS[scanner_uuid].friendly_name or scanner_uuid} @ {SCANNERS[scanner_uuid].ip} for {EndTo_id}")
    else:
        logger.info(f"no search result for {EndTo_id}")
        return web.Response(status=400, text="bad notify endpoint")

    scanjob_identifier = None
    try:
        root = ET.fromstring(xml_payload)
        scanjob_identifier = parse_notify_msg(scanner_uuid, xml_payload)      # hier werden die Metadaten zum Abholauftrag zusammengetragen
    except Exception as e:
        logger.warning(f"[SERVER:notify_handler] invalid xml: {e}")
        return web.Response(status=400, text="bad xml")

    if not scanjob_identifier:
        return web.Response(status=400, text="could not extract any scanjob identifier from xml")
    
    logger.info(f"scheduling scan job {scanjob_identifier} for scanner {SCANNERS[scanner_uuid].friendly_name or scanner_uuid}")

    loop = asyncio.get_event_loop()
    loop.call_soon(asyncio.create_task, run_scan_job(scanjob_identifier))
    logger.debug(f"task should start soon...!")

    return web.Response(status=202, text="Alles juut")


#
#
# --------------------------------------------------
# ---------------- END OF SERVER.PY ----------------
