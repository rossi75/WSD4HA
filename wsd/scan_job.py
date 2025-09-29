# ---------------- take the document ----------------
async def fetch_scanned_document(scanner_uuid, doc_uuid):
    """
    Holt das gescannte Dokument asynchron ab.
    """
    logger.info(f"[JOB:fetch] starting Download from {SCANNER[scanner_uuid].friendly_name}")

    download_url = f"http://{scanner.ip}:80/ScanDocument"   # Beispiel-URL

    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(download_url, timeout=30) as resp:
                if resp.status == 200:
                    data = await resp.read()
                    save_path = f"/tmp/{scanner_uuid}_scan.jpg"
                    with open(save_path, "wb") as f:
                        f.write(data)
                    logger.info(f"[FETCH] Scan von {scanner.friendly_name} gespeichert: {save_path}")
                else:
                    logger.warning(f"[FETCH] Download fehlgeschlagen ({resp.status})")
    except Exception as e:
        logger.exception(f"[FETCH] Fehler beim Download: {e}")


# ---------------- HTTP/SOAP Server ----------------
async def handle_scan_job(request):
    logger.info(f"{datetime.datetime.now():%Y-%m-%d %H:%M:%S} [SCAN] Scan-Job started")
    data = await request.read()
    logger.info(f"{datetime.datetime.now():%Y-%m-%d %H:%M:%S} [SCAN] Received first Bytes: {len(data)}")
    #logger.debug(f"[SCAN] Received first Bytes: {len(data)}")
    filename = WSD_SCAN_FOLDER / f"scan-{datetime.datetime.now():%Y%m%d_%H%M%S}.bin"
    try:
        with open(filename, "wb") as f:
            f.write(data)
        logger.info(f"{datetime.datetime.now():%Y-%m-%d %H:%M:%S} [SCAN] Scan finished: {filename} ({len(data)/1024:.1f} KB)")
    except Exception as e:
        logger.error(f"{datetime.datetime.now():%Y-%m-%d %H:%M:%S} [SCAN] Error while saving: {e}")
    return web.Response(text="""
        <soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope">
            <soap:Body>
                <ScanJobResponse>OK</ScanJobResponse>
            </soap:Body>
        </soap:Envelope>
    """, content_type='application/soap+xml')
