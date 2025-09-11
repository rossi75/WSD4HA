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
