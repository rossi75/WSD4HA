# polling.py (Beispiel)
import asyncio, datetime, uuid, aiohttp
from pathlib import Path
from globals import SCANNERS, SCAN_JOBS, STATE, WSD_SCAN_FOLDER, MAX_SEMAPHORE, logger

WSD_SCAN_FOLDER.mkdir(parents=True, exist_ok=True)
SEMAPHORE = asyncio.Semaphore(MAX_SEMAPHORE)   # max parallel downloads

# ----------------- Request Scan Job -----------------
async def request_scan_job(job_id: str):
    logger.info(f"[SCAN_JOB] received request for job {job_id}")

    if job_id not in SCAN_JOBS:
        logger.warning(f"could not find any existing job with ID {job_id}. Skipping request")
        SCAN_JOB[job_id].status = STATE.SCAN_FAILED
        return
    else:
        if SCAN_JOB[job_id].status == STATE.SCAN_PENDING
            SCAN_JOB[job_id].status == STATE.SCAN_REQUESTING



        
    logger.info(f"[JOB] started polling task for {job_id}")

    scanner_uuid = job["scanner_uuid"]
    scanner = SCANNERS.get(scanner_uuid)
    if not scanner:
        logger.error(f"[JOB] unknown scanner {scanner_uuid}")
        job["status"] = "failed"
        return

    # Polling schedule: fast then slower
    intervals = [0.5]*10 + [2.0]*30 + [10.0]*18  # insgesamt ~10min
    for interval in intervals:
        job["last_try"] = datetime.datetime.now().replace(microsecond=0)
        job["retries"] += 1
        logger.debug(f"[JOB] try #{job['retries']} for {job_id}, interval {interval}s")

        # choose URL: explicit download_url or fallback to scanner.xaddr + "/scan"
        urls_to_try = []
        if job.get("xaddr"):
            urls_to_try.append(job["xaddr"])
        # fallback: take scanner.xaddr and ensure /scan
        if scanner.xaddr:
            # scanner.xaddr could be "http://192.168.0.3:8018/wsd"
            base = scanner.xaddr.rstrip('/')
            # try /wsd/scan and /scan
            urls_to_try.append(base + "/wsd/scan")
            urls_to_try.append(base + "/scan")
            urls_to_try.append(f"http://{scanner.ip}:80/StableWSDiscoveryEndpoint/schemas-xmlsoap-org_ws_2005_04_discovery")

        got_file = False
        async with SEMAPHORE:
            async with aiohttp.ClientSession() as session:
                for url in urls_to_try:
                    try:
                        logger.debug(f"[JOB] trying GET {url}")
                        async with session.get(url, timeout=6) as resp:
                            if resp.status != 200:
                                logger.debug(f"[JOB] {url} -> {resp.status}")
                                continue
                            data = await resp.read()
                            if not data or len(data) < 100:   # very small -> probably not ready
                                logger.debug(f"[JOB] {url} returned too small payload ({len(data)} bytes)")
                                continue
                            # OPTIONAL: check magic bytes for JPEG/JFIF/PDF
                            if data.startswith(b'\xFF\xD8\xFF') or data[:4]==b'%PDF':
                                filename = f"scan-{datetime.datetime.now():%Y%m%d-%H%M%S}-{job_id}.jpg"
                                path = Path(WSD_SCAN_FOLDER) / filename
                                with open(path, "wb") as f:
                                    f.write(data)
                                job["status"] = "done"
                                job["path"] = str(path)
                                logger.info(f"[JOB] downloaded {job_id} -> {path}")
                                got_file = True
                                break
                            else:
                                # if content-type or magic doesn't match, still store maybe as .bin or skip
                                logger.debug(f"[JOB] {url}: unknown payload signature, len={len(data)}")
                    except Exception as e:
                        logger.debug(f"[JOB] exception GET {url}: {e}")

        if got_file:
            # optional: signal paperless / OCR pipeline here
            # cleanup
            # remove job from dict or keep for history
            # SCAN_JOBS.pop(job_id, None)
            return

        # not yet ready, wait next interval
        await asyncio.sleep(interval)

    # if loop finished without success:
    job["status"] = "failed"
    logger.warning(f"[JOB] give up on {job_id} after {job['retries']} tries")

# ---------------- take the document ----------------
async def fetch_scanned_document(scanner_uuid, doc_uuid):
    """
    Holt das gescannte Dokument asynchron ab.
    """
    logger.info(f"[JOB:fetch] retrieving document from {SCANNER[scanner_uuid].friendly_name}")
    logger.info(f"   ---> doc ID: {doc_uuid}")

    url = SCANNERS[scanner_uuid].xaddr
    msg_id = uuid.uuid4()

    headers = {
        "Content-Type": "application/soap+xml",
        "User-Agent": USER_AGENT
    }

    body = TEMPLATE_RETRIEVE_DOCUMENT.format(
        xaddr = SCANNERS[scanner_uuid].xaddr,
        msg_id = msg_id,
        scan_identifier = doc_uuid
    )

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
