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
from wsd import discovery_listener, heartbeat_monitor, handle_scan_job
from config import WSD_HTTP_PORT, WSD_OFFLINE_TIMEOUT, WSD_SCAN_FOLDER

logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')
logger = logging.getLogger("wsd-addon")

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
