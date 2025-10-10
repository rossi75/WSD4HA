import asyncio
import datetime
import uuid
import aiohttp
from pathlib import Path
#from globals import SCANNERS, SCAN_JOBS, STATE, WSD_SCAN_FOLDER, MAX_SEMAPHORE, logger
from globals import SCANNERS, SCAN_JOBS, STATE, WSD_SCAN_FOLDER, logger

#import datetime
#import logging
import os
import re
import socket
#import subprocess
import sys
#import time
#import threading
import uuid
#import xml.etree.ElementTree as ET

#from config import OFFLINE_TIMEOUT, LOCAL_IP, HTTP_PORT, FROM_UUID, DISPLAY, NOTIFY_PORT, get_local_ip
#from globals import SCANNERS, list_scanners, NAMESPACES, STATE, USER_AGENT, LOG_LEVEL
from config import OFFLINE_TIMEOUT, LOCAL_IP, HTTP_PORT, FROM_UUID, DISPLAY, NOTIFY_PORT
from globals import SCANNERS, SCAN_JOBS, NAMESPACES, WSD_SCAN_FOLDER, STATE, USER_AGENT, LOG_LEVEL
#from parse import parse_wsd_packet, parse_probe, parse_transfer_get, parse_subscribe
from pathlib import Path
from scanner import Scanner, Scan_Jobs
from tools import list_scanners, get_local_ip
from templates import TEMPLATE_CREATE_SCANJOB


#WSD_SCAN_FOLDER.mkdir(parents=True, exist_ok=True)
#SEMAPHORE = asyncio.Semaphore(MAX_SEMAPHORE)   # max parallel downloads

###################################################################################
# Create/Request Scan Job Ticket
# ---------------------------------------------------------------------------------
# Parameters:
# job_id = scan job identifier
# ---------------------------------------------------------------------------------
async def request_scan_job_ticket(job_id: str):
    logger.info(f"{datetime.datetime.now():%Y-%m-%d %H:%M:%S} [SCAN_JOB:ticket] creating/requesting ticket for scan job {job_id}")

    if job_id not in SCAN_JOBS:
        logger.warning(f"could not find any existing job with ID {job_id}. Skipping request")
        SCAN_JOB[job_id].status = STATE.SCAN_FAILED
        return
    else:
        if SCAN_JOB[job_id].status == STATE.SCAN_PENDING:
            SCAN_JOB[job_id].status == STATE.SCAN_REQ_TICKET

    scanner_uuid = SCAN_JOBS[job_id].scan_from_uuid

#        self.scanjob_identifier = scan_job_id
#        self.input_source = input_source
#        self.scan_from_uuid = scan_from_uuid
#        self.subscription_identifier = SCANNERS[scan_from_uuid].subscription_id
#        self.xaddr = SCANNERS[scan_from_uuid].xaddr
#        self.dest_token = SCANNERS[scan_from_uuid].destination_token
# xaddr = destination adress
# msg_id = random message ID
# from_uuid = sender UUID
# scan_identifier = Scan Identifier from xml notification dialog
# destination_token = token given by scanner while registration

    body = ""
    msg_id = uuid.uuid4()
    url = SCAN_JOBS[job_id].xaddr  # z.B. http://192.168.0.3:8018/wsd

    xml = TEMPLATE_CREATE_SCANJOB.format(
        xaddr = url,
        msg_id = msg_id,
        from_uuid = FROM_UUID,
        scan_identifier = SCAN_JOBS[job_id].scanjob_identifier,
        subscription_identifier = SCAN_JOBS[job_id].subscription_identifier,
        destination_token = SCAN_JOBS[job_id].destination_token,
        DocPar_FileFormat = SCANNERS[scanner_uuid].DocPar_FileFormat,
        DocPar_InputSource = SCANNERS[scanner_uuid].DocPar_InputSource,
        DocPar_InputWidth = SCANNERS[scanner_uuid].DocPar_InputWidth,
        DocPar_InputHeight = SCANNERS[scanner_uuid].DocPar_InputHeight,
        DocPar_RegionWidth = SCANNERS[scanner_uuid].DocPar_RegionWidth,
        DocPar_RegionHeight = SCANNERS[scanner_uuid].DocPar_RegionHeight,
        DocPar_ResolutionWidth = SCANNERS[scanner_uuid].DocPar_ResolutionWidth,
        DocPar_ResolutionHeight = SCANNERS[scanner_uuid].DocPar_ResolutionHeight,
        DocPar_ExposureContrast = SCANNERS[scanner_uuid].DocPar_ExposureContrast,
        DocPar_ExposureBrightness = SCANNERS[scanner_uuid].DocPar_ExposureBrightness,
        DocPar_ScalingWidth = SCANNERS[scanner_uuid].DocPar_ScalingWidth,
        DocPar_ScalingHeight = SCANNERS[scanner_uuid].DocPar_ScalingHeight,
        DocPar_Rotation = SCANNERS[scanner_uuid].DocPar_Rotation,
        DocPar_RegionXOffset = SCANNERS[scanner_uuid].DocPar_RegionXOffset,
        DocPar_RegionYOffset = SCANNERS[scanner_uuid].DocPar_RegionYOffset,
        DocPar_ColorProcessing = SCANNERS[scanner_uuid].DocPar_ColorProcessing
    )
    headers = {
        "Content-Type": "application/soap+xml",
        "User-Agent": USER_AGENT
    }

    logger.debug(f"   --->      FROM: {FROM_UUID}")
    logger.debug(f"   --->    MSG_ID: {msg_id}")
    logger.info(f"   --->       URL: {url}")
    logger.info(f"   --->       XML:\n{xml}")

    async with aiohttp.ClientSession() as session:
        try:
            async with session.post(url, data=xml, headers=headers, timeout=5) as resp:
                if resp.status == 200:
                    body = await resp.text()
                else:
                    SCAN_JOBS[job_id].state = STATE.SCAN_FAILED
                    logger.error(f"[SCAN_JOB:ticket] Request for ticket failed with Statuscode {resp.status}")
                    return
        except Exception as e:
            logger.error(f"[SCAN_JOB:ticket] anything went wrong with {SCAN_JOB[job_id]}: {e}")
            SCAN_JOBS[job_id].state = STATE.SCAN_FAILED
            return

    logger.info(f"trying to parse the ticket answer")
    
    asyncio.create_task(parse_request_scan_job_ticket(job_id, body))


async def _create_scan_job_ticket(renew_uuid: str):
    logger.info(f"{datetime.datetime.now():%Y-%m-%d %H:%M:%S} [SEND:subscr_rnw] renewing subscription for {SCANNERS[renew_uuid].friendly_name or renew_uuid} @ {SCANNERS[renew_uuid].ip}")
    
    SCANNERS[renew_uuid].state = STATE.SUBSCRIBING_SCAN_AVAIL_EVT

    body = ""
    msg_id = uuid.uuid4()
    ref_id = SCANNERS[renew_uuid].subscription_ref
    EndToAddr = SCANNERS[renew_uuid].end_to_addr
    url = SCANNERS[renew_uuid].xaddr  # z.B. http://192.168.0.3:8018/wsd
    xml = TEMPLATE_SUBSCRIBE_RENEW.format(
        to_device_uuid = renew_uuid,
        msg_id = msg_id,
        from_uuid = FROM_UUID,
        xaddr = SCANNERS[renew_uuid].xaddr,
        EndTo_addr = EndToAddr,
        scan_to_name = DISPLAY,
        Ref_ID = ref_id
    )
    headers = {
        "Content-Type": "application/soap+xml",
        "User-Agent": USER_AGENT
    }

    logger.debug(f"   --->      FROM: {FROM_UUID}")
    logger.debug(f"   --->        TO: {renew_uuid}")
    logger.debug(f"   --->    MSG_ID: {msg_id}")
    logger.debug(f"   ---> subscr_ID: {ref_id}")
    logger.debug(f"   --->    End_To: {EndToAddr}")
    logger.debug(f"   --->       URL: {url}")
    logger.debug(f"   --->       XML:\n{xml}")

    async with aiohttp.ClientSession() as session:
        try:
            async with session.post(url, data=xml, headers=headers, timeout=5) as resp:
                if resp.status == 200:
                    body = await resp.text()
                else:
                    SCANNERS[renew_uuid].state = STATE.ERROR
                    logger.error(f"[SEND:rnw] Renew to ScanAvailableEvents failed with Statuscode {resp.status}")
                    return None
        except Exception as e:
            logger.error(f"[SEND:rnw] failed for {SCANNERS[renew_uuid].uuid}: {e}")
            SCANNERS[renew_uuid].state = STATE.ERROR
            return None
 
    parse_subscribe(renew_uuid, body)


    
    
    
# ----------------- Request Scan Job -----------------
async def _request_scan_ticket(job_id: str):

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
async def _fetch_scanned_document(scanner_uuid, doc_uuid):
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
async def _handle_scan_job(request):
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

#
#
# *****************************************************
# **************** END OF SCAN_JOB.PY  ****************
