import asyncio
import aiohttp
import datetime
import os
import time
import threading
import uuid
import xml.etree.ElementTree as ET
from config import OFFLINE_TIMEOUT, LOCAL_IP, HTTP_PORT, FROM_UUID, DISPLAY, NOTIFY_PORT
from globals import SCANNERS, SCAN_JOBS, NAMESPACES, STATE, USER_AGENT, logger
from parse import parse_wsd_packet, parse_probe, parse_transfer_get, parse_subscribe, parse_get_scanner_elements_default_ticket, parse_create_scan_job, parse_retrieve_image
from pathlib import Path
from tools import list_scanners, get_local_ip
from templates import TEMPLATE_PROBE, TEMPLATE_TRANSFER_GET, TEMPLATE_SUBSCRIBE_SAE, TEMPLATE_SUBSCRIBE_RENEW, TEMPLATE_GET_SCANNER_ELEMENTS_STATE, TEMPLATE_GET_SCANNER_ELEMENTS_CONFIGURATION, TEMPLATE_GET_SCANNER_ELEMENTS_DEFAULT_TICKET, TEMPLATE_VALIDATE_SCAN_TICKET_DETAIL, TEMPLATE_CREATE_SCANJOB, TEMPLATE_RETRIEVE_DOCUMENT

# ---------------- Send Scanner Probe ----------------
async def send_probe(probe_uuid: str):
    logger.info(f"{datetime.datetime.now():%Y-%m-%d %H:%M:%S} [SEND:send_probe] sending probe for {SCANNERS[probe_uuid].friendly_name} @ {SCANNERS[probe_uuid].ip}")

    SCANNERS[probe_uuid].state = STATE.PROBING

    msg_id = uuid.uuid4()
    body = ""
    xml = TEMPLATE_PROBE.format(msg_id=msg_id)
    headers = {
        "Content-Type": "application/soap+xml",
        "User-Agent": USER_AGENT
    }
    url = f"http://{SCANNERS[probe_uuid].ip}:80/StableWSDiscoveryEndpoint/schemas-xmlsoap-org_ws_2005_04_discovery"

    logger.debug(f"   ---> URL: {url}")
    logger.debug(f"   ---> XML:\n{xml}")

    async with aiohttp.ClientSession() as session:
        try:
            async with session.post(url, data=xml, headers=headers, timeout=5) as resp:
                if resp.status == 200:
                    body = await resp.text()
                else:
                    logger.error(f"Probe failed with status {resp.status}")
                    SCANNERS[uuid].state = STATE.ABSENT
        except Exception as e:
            logger.error(f"   ---> Probe failed at {url}: {e}")
            SCANNERS[probe_uuid].state = STATE.ABSENT

    logger.debug(f"ProbeMatch from {SCANNERS[probe_uuid].ip}:\n{body}")

    parse_probe(body, probe_uuid)


# ---------------- Send Transfer_Get ----------------
async def send_transfer_get(tf_g_uuid: str):
    logger.info(f"{datetime.datetime.now():%Y-%m-%d %H:%M:%S} [SEND:transfer_get] sending Transfer/Get to {tf_g_uuid} @ {SCANNERS[tf_g_uuid].ip}")
    
    SCANNERS[tf_g_uuid].state = STATE.TF_GET_PENDING

    body = ""
    msg_id = uuid.uuid4()
    xml = TEMPLATE_TRANSFER_GET.format(
        to_device_uuid=tf_g_uuid,
        msg_id=msg_id,
        from_uuid=FROM_UUID
    )
    headers = {
        "Content-Type": "application/soap+xml",
        "User-Agent": USER_AGENT
    }
    url = SCANNERS[tf_g_uuid].xaddr  # z.B. http://192.168.0.3:8018/wsd

    logger.debug(f"   --->    FROM: {FROM_UUID}")
    logger.debug(f"   --->      TO: {tf_g_uuid}")
    logger.debug(f"   --->  MSG_ID: {msg_id}")
    logger.debug(f"   --->     URL: {url}")
    logger.debug(f"   --->     XML:\n{xml}")

    async with aiohttp.ClientSession() as session:
        try:
            async with session.post(url, data=xml, headers=headers, timeout=5) as resp:
                if resp.status == 200:
                    body = await resp.text()
                else:
                    SCANNERS[tf_g_uuid].state = STATE.ERROR
                    logger.error(f"[WSD:transfer_get] TransferGet failed with Statuscode {resp.status}")
                    return None
        except Exception as e:
            logger.error(f"[WSD:transfer_get] failed for {SCANNERS[tf_g_uuid].uuid}: {e}")
            SCANNERS[tf_g_uuid].state = STATE.ERROR
            return None
 
    logger.debug(f"TransferGet von {SCANNERS[tf_g_uuid].ip}:\n{body}")
    parse_transfer_get(body, tf_g_uuid)


###################################################################################
# Subscribe ScanAvailableEvent
# ---------------------------------------------------------------------------------
# Parameters:
# sae_uuis = scanners endpoint UUID
# ---------------------------------------------------------------------------------
async def send_subscription_ScanAvailableEvent(sae_uuid: str):
    logger.info(f"{datetime.datetime.now():%Y-%m-%d %H:%M:%S} [SEND:subscr_sae] subscribing ScanAvailableEvent to {SCANNERS[sae_uuid].friendly_name or sae_uuid} @ {SCANNERS[sae_uuid].ip}")
    
    SCANNERS[sae_uuid].state = STATE.SUBSCRIBING_SCAN_AVAIL_EVT

    body = ""
    msg_id = uuid.uuid4()
    ref_id = uuid.uuid4()
    addr_id = uuid.uuid4()
    url = SCANNERS[sae_uuid].xaddr  # z.B. http://192.168.0.3:8018/wsd
    if SCANNERS[sae_uuid].end_to_addr is None:
#        SCANNERS[sae_uuid].end_to_addr = f"http://192.168.0.10:5357/{addr_id}"
        SCANNERS[sae_uuid].end_to_addr = f"http://{get_local_ip()}:{NOTIFY_PORT}/{addr_id}"
        logger.info(f"created new end_to_addr")
    else:
        logger.info(f"using existing end_to_addr")

    headers = {
        "Content-Type": "application/soap+xml",
        "User-Agent": USER_AGENT
    }
    xml = TEMPLATE_SUBSCRIBE_SAE.format(
        to_device_uuid = sae_uuid,
        msg_id = msg_id,
        from_uuid = FROM_UUID,
        xaddr = SCANNERS[sae_uuid].xaddr,
        EndTo_addr = SCANNERS[sae_uuid].end_to_addr,
        scan_to_name = DISPLAY,
        Ref_ID = ref_id
    )

    logger.debug(f"   --->     URL: {url}")
    logger.debug(f"   --->    FROM: {FROM_UUID}")
    logger.debug(f"   --->      TO: {sae_uuid}")
    logger.debug(f"   --->  MSG_ID: {msg_id}")
    logger.debug(f"   --->  REF_ID: {ref_id}")
    logger.debug(f"   --->  NAMEoD: {DISPLAY}")
    logger.debug(f"   --->  End_To: {SCANNERS[sae_uuid].end_to_addr}")
    logger.debug(f"   --->     XML:\n{xml}")

    async with aiohttp.ClientSession() as session:
        try:
            async with session.post(url, data=xml, headers=headers, timeout=5) as resp:
                if resp.status == 200:
                    body = await resp.text()
                else:
                    SCANNERS[sae_uuid].state = STATE.ERROR
                    logger.error(f"[SEND:sae] Subscribe to ScanAvailableEvents failed with Statuscode {resp.status}")
                    return None
        except Exception as e:
            logger.error(f"[SEND:sae] failed for {SCANNERS[tf_g_uuid].uuid}: {e}")
            SCANNERS[tf_g_uuid].state = STATE.ERROR
            return None
 
    parse_subscribe(sae_uuid, body)

###################################################################################
# Subscription Renew
# ---------------------------------------------------------------------------------
# Parameters:
# renew_uuid = scanners endpoint UUID
# ---------------------------------------------------------------------------------
async def send_subscription_renew(renew_uuid: str):
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


###################################################################################
# GetScannerElements[State] before requesting a ticket, do nothing while not in IDLE
# ---------------------------------------------------------------------------------
# Parameters:
# scan_from_uuid = Scanners uuid, but taken from the scan job
# ---------------------------------------------------------------------------------
async def request_scanner_elements_state(scanjob_identifier: str):
    logger.info(f"{datetime.datetime.now():%Y-%m-%d %H:%M:%S} [SEND:gse_state] asking scanner about its state for scan job {scanjob_identifier}")

    if scanjob_identifier not in SCAN_JOBS:
        logger.warning(f"could not find any existing job with ID {scanjob_identifier}. Skipping state request")
        SCAN_JOBS[scanjob_identifier].status = STATE.SCAN_FAILED
        return False
    else:
#        SCAN_JOBS[scanjob_identifier].status == STATE.REQ_SCAN_STATE
        return True

    # tbd
    body = ""
    msg_id = uuid.uuid4()
    url = SCAN_JOBS[scanjob_identifier].xaddr  # z.B. http://192.168.0.3:8018/wsd

    xml = TEMPLATE_GET_SCANNER_ELEMENTS_STATE.format(
        xaddr = url,
        msg_id = msg_id,
        from_uuid = FROM_UUID,
    )
    headers = {
        "Content-Type": "application/soap+xml",
        "User-Agent": USER_AGENT
    }

    logger.debug(f"   --->        FROM: {FROM_UUID}")
    logger.debug(f"   --->      MSG_ID: {msg_id}")
    logger.debug(f"   --->         URL: {url}")
    logger.info(f"   ---> Request XML:\n{xml}")

    async with aiohttp.ClientSession() as session:
        try:
            async with session.post(url, data=xml, headers=headers, timeout=5) as resp:
                if resp.status == 200:
                    body = await resp.text()
                else:
                    SCAN_JOBS[job_id].state = STATE.SCAN_FAILED
                    logger.error(f"[SEND:def_ticket] Request for scanners state failed with Statuscode {resp.status}")
                    return false
        except Exception as e:
            logger.error(f"[SEND:def_ticket] anything went wrong with scanners state for scan job {SCAN_JOBS[scanjob_identifier]}:\n{e}")
            SCAN_JOBS[scanjob_identifier].state = STATE.SCAN_FAILED
            return false

    logger.info(f"trying to parse the scanners state")
    logger.debug(f"   --->  Answer XML:\n{body}")
    
    result = parse_get_scanner_elements_state(scanjob_identifier, body)

    logger.info(f" Result from parsing: {result}")

    return result


###################################################################################
# GetScannerElements[ScannerConfiguration]
# ---------------------------------------------------------------------------------
# Parameters:
# scan_from_uuid = Scanners uuid, but taken from the scan job
# ---------------------------------------------------------------------------------
async def request_scanner_elements_scanner_configuration(scanjob_identifier: str):
    logger.info(f"{datetime.datetime.now():%Y-%m-%d %H:%M:%S} [SEND:gse_scan_config] asking scanner about its configuration (explicit for maxWidth and maxHeight) {scanjob_identifier}")

    if scanjob_identifier not in SCAN_JOBS:
        logger.warning(f"could not find any existing job with ID {scanjob_identifier}. Skipping configuration request")
        SCAN_JOBS[scanjob_identifier].status = STATE.SCAN_FAILED
        return False
#    else:
#        SCAN_JOBS[scanjob_identifier].status == STATE.REQ_SCAN_STATE
#        return True

    # tbd
    body = ""
    msg_id = uuid.uuid4()
    url = SCAN_JOBS[scanjob_identifier].xaddr  # z.B. http://192.168.0.3:8018/wsd

    xml = TEMPLATE_GET_SCANNER_ELEMENTS_SCANNER_CONFIGURATION.format(
        xaddr = url,
        msg_id = msg_id,
        from_uuid = FROM_UUID,
    )
    headers = {
        "Content-Type": "application/soap+xml",
        "User-Agent": USER_AGENT
    }

    logger.debug(f"   --->        FROM: {FROM_UUID}")
    logger.debug(f"   --->      MSG_ID: {msg_id}")
    logger.debug(f"   --->         URL: {url}")
    logger.debug(f"   ---> Request XML:\n{xml}")

    async with aiohttp.ClientSession() as session:
        try:
            async with session.post(url, data=xml, headers=headers, timeout=5) as resp:
                if resp.status == 200:
                    body = await resp.text()
                else:
                    SCAN_JOBS[job_id].state = STATE.SCAN_FAILED
                    logger.error(f"[SEND:scan_config] Request for scanners configuration failed with Statuscode {resp.status}")
                    return false
        except Exception as e:
            logger.error(f"[SEND:scan_config] anything went wrong with scanners configuration for scan job {SCAN_JOBS[scanjob_identifier]}:\n{e}")
            SCAN_JOBS[scanjob_identifier].state = STATE.SCAN_FAILED
            return false

    logger.info(f"trying to parse the scanners configuration")
    logger.debug(f"   --->  Answer XML:\n{body}")
    
    result = parse_get_scanner_elements_configuration(scanjob_identifier, body)

    logger.info(f" Result from parsing: {result}")

    return result




###################################################################################
# GetScannerElements[DefaultScanTicket]
# ---------------------------------------------------------------------------------
# Parameters:
# scan_from_uuid = Scanners uuid, but taken from the scan job
# ---------------------------------------------------------------------------------
async def request_scanner_elements_def_ticket(scanjob_identifier: str):
    logger.info(f"{datetime.datetime.now():%Y-%m-%d %H:%M:%S} [SEND:def_ticket] asking scanner about its default ticket for scan job {scanjob_identifier}")

    if scanjob_identifier not in SCAN_JOBS:
        logger.warning(f"could not find any existing job with ID {scanjob_identifier}. Skipping request")
#        SCAN_JOBS[scanjob_identifier].status = STATE.SCAN_FAILED
        return False
 #   else:
 #       SCAN_JOBS[scanjob_identifier].status == STATE.REQ_DEF_TICKET

    body = ""
    msg_id = uuid.uuid4()
    url = SCAN_JOBS[scanjob_identifier].xaddr  # z.B. http://192.168.0.3:8018/wsd

    xml = TEMPLATE_GET_SCANNER_ELEMENTS_DEFAULT_TICKET.format(
        xaddr = url,
        msg_id = msg_id,
        from_uuid = FROM_UUID,
    )
    headers = {
        "Content-Type": "application/soap+xml",
        "User-Agent": USER_AGENT
    }

    logger.debug(f"   --->        FROM: {FROM_UUID}")
    logger.debug(f"   --->      MSG_ID: {msg_id}")
    logger.debug(f"   --->         URL: {url}")
    logger.debug(f"   ---> Request XML:\n{xml}")

    async with aiohttp.ClientSession() as session:
        try:
            async with session.post(url, data=xml, headers=headers, timeout=5) as resp:
                if resp.status == 200:
                    body = await resp.text()
                else:
                    SCAN_JOBS[job_id].state = STATE.SCAN_FAILED
                    logger.error(f"[SEND:def_ticket] Request for default ticket failed with Statuscode {resp.status}")
                    return false
        except Exception as e:
            logger.error(f"[SEND:def_ticket] anything went wrong with Scan Job {SCAN_JOBS[scanjob_identifier]}:\n{e}")
            SCAN_JOBS[scanjob_identifier].state = STATE.SCAN_FAILED
            return false

    logger.info(f"trying to parse the default ticket answer")
    logger.debug(f"   --->  Answer XML:\n{body}")
    
    result = parse_get_scanner_elements_default_ticket(scanjob_identifier, body)

    logger.info(f" Result from parsing: {result}")

    return result


###################################################################################
# ValidateScanTicket Detail
# ---------------------------------------------------------------------------------
# Parameters:
# scan_from_uuid = Scanners uuid, but taken from the scan job
# ---------------------------------------------------------------------------------
async def request_validate_scan_ticket(scanjob_identifier: str):
    logger.info(f"{datetime.datetime.now():%Y-%m-%d %H:%M:%S} [SEND:validate_scan_ticket] validating scan ticket for scan job {scanjob_identifier}")

    if scanjob_identifier not in SCAN_JOBS:
        logger.warning(f"could not find any existing job with ID {scanjob_identifier}. Skipping state request")
        SCAN_JOBS[scanjob_identifier].status = STATE.SCAN_FAILED
        return False
    else:
        return True

    # tbd


###################################################################################
# Create/Request Scan Job Ticket
# ---------------------------------------------------------------------------------
# Parameters:
# job_id = scan job identifier
# ---------------------------------------------------------------------------------
async def request_scan_job_ticket(scanjob_identifier: str):
    logger.info(f"{datetime.datetime.now():%Y-%m-%d %H:%M:%S} [SEND:sj_ticket] creating/requesting Ticket ID and Token for scan job {scanjob_identifier}")

    if scanjob_identifier not in SCAN_JOBS:
        logger.warning(f"could not find any existing job with ID {scanjob_identifier}. Skipping request")
#        SCAN_JOBS[scanjob_identifier].status = STATE.SCAN_FAILED
        return
#    else:
#        if SCAN_JOBS[scanjob_identifier].status == STATE.SCAN_PENDING:
#            SCAN_JOBS[scanjob_identifier].status == STATE.SCAN_REQ_TICKET

    scanner_uuid = SCAN_JOBS[scanjob_identifier].scan_from_uuid

    body = ""
    msg_id = uuid.uuid4()
    url = SCAN_JOBS[scanjob_identifier].xaddr  # z.B. http://192.168.0.3:8018/wsd

    xml = TEMPLATE_CREATE_SCANJOB.format(
        xaddr = url,
        msg_id = msg_id,
        from_uuid = FROM_UUID,
        scan_identifier = SCAN_JOBS[scanjob_identifier].scanjob_identifier,
        subscription_identifier = SCAN_JOBS[scanjob_identifier].subscription_identifier,
        destination_token = SCAN_JOBS[scanjob_identifier].destination_token,
        DocPar_InputSource = SCAN_JOBS[scanjob_identifier].input_source,
        DocPar_FileFormat = SCAN_JOBS[scanjob_identifier].DocPar_FileFormat,
        DocPar_ImagesToTransfer = SCAN_JOBS[scanjob_identifier].DocPar_ImagesToTransfer,
        DocPar_InputWidth = SCAN_JOBS[scanjob_identifier].DocPar_InputWidth,
        DocPar_InputHeight = SCAN_JOBS[scanjob_identifier].DocPar_InputHeight,
        DocPar_RegionWidth = SCAN_JOBS[scanjob_identifier].DocPar_RegionWidth,
        DocPar_RegionHeight = SCAN_JOBS[scanjob_identifier].DocPar_RegionHeight,
        DocPar_ResolutionWidth = SCAN_JOBS[scanjob_identifier].DocPar_ResolutionWidth,
        DocPar_ResolutionHeight = SCAN_JOBS[scanjob_identifier].DocPar_ResolutionHeight,
        DocPar_ExposureContrast = SCAN_JOBS[scanjob_identifier].DocPar_ExposureContrast,
        DocPar_ExposureBrightness = SCAN_JOBS[scanjob_identifier].DocPar_ExposureBrightness,
        DocPar_ScalingWidth = SCAN_JOBS[scanjob_identifier].DocPar_ScalingWidth,
        DocPar_ScalingHeight = SCAN_JOBS[scanjob_identifier].DocPar_ScalingHeight,
        DocPar_Rotation = SCAN_JOBS[scanjob_identifier].DocPar_Rotation,
        DocPar_RegionXOffset = SCAN_JOBS[scanjob_identifier].DocPar_RegionXOffset,
        DocPar_RegionYOffset = SCAN_JOBS[scanjob_identifier].DocPar_RegionYOffset,
        DocPar_ColorProcessing = SCAN_JOBS[scanjob_identifier].DocPar_ColorProcessing
    )
    headers = {
        "Content-Type": "application/soap+xml",
        "User-Agent": USER_AGENT
    }

    logger.debug(f"   --->        FROM: {FROM_UUID}")
    logger.debug(f"   --->      MSG_ID: {msg_id}")
    logger.info(f"   --->         URL: {url}")
    logger.info(f"   ---> Request XML:\n{xml}")

    async with aiohttp.ClientSession() as session:
        try:
            async with session.post(url, data=xml, headers=headers, timeout=5) as resp:
                if resp.status == 200:
                    body = await resp.text()
                else:
                    SCAN_JOBS[job_id].state = STATE.SCAN_FAILED
                    logger.error(f"[SCAN_JOB:ticket] Request for ticket failed with Statuscode {resp.status}")
                    return false
        except Exception as e:
            logger.error(f"[SCAN_JOB:ticket] anything went wrong with {SCAN_JOBS[scanjob_identifier]}: {e}")
            SCAN_JOBS[scanjob_identifier].state = STATE.SCAN_FAILED
            return false

    logger.info(f"trying to parse the ticket answer")
    logger.info(f"   --->  Answer XML:\n{body}")
    
#    result = asyncio.create_task(parse_request_scan_job_ticket(scanjob_identifier, body))
#    result = parse_request_scan_job_ticket(scanjob_identifier, body)
    result = parse_create_scan_job(scanjob_identifier, body)

    logger.info(f" Result from parsing: {result}")

    return result


###################################################################################
# retrieve image from scanner
# ---------------------------------------------------------------------------------
# Parameters:
# scanjob_identifier = scan job identifier
# ---------------------------------------------------------------------------------
async def request_retrieve_image(scanjob_identifier: str):
    logger.info(f"{datetime.datetime.now():%Y-%m-%d %H:%M:%S} [SEND:rtrv_img] retrieving image for scan job {job_id}")

    if scanjob_identifier not in SCAN_JOBS:
        logger.warning(f"could not find any existing job with ID {scanjob_identifier}. Skipping retrieve image")
        SCAN_JOBS[scanjob_identifier].status = STATE.SCAN_FAILED
        return

    SCAN_JOBS[scanjob_identifier].status == STATE.SCAN_RETRIEVE_IMG

    scanner_uuid = SCAN_JOBS[scanjob_identifier].scan_from_uuid

    body = ""
    msg_id = uuid.uuid4()
    url = SCAN_JOBS[scanjob_identifier].xaddr  # z.B. http://192.168.0.3:8018/wsd

    xml = TEMPLATE_RETRIEVE_DOCUMENT.format(
        xaddr = url,
        msg_id = msg_id,
        from_uuid = FROM_UUID,
        JobID = SCAN_JOBS[scanjob_identifier].job_id,
        JobToken = SCAN_JOBS[scanjob_identifier].job_token,
    )
    headers = {
        "Content-Type": "application/soap+xml",
        "User-Agent": USER_AGENT
    }

    logger.debug(f"   --->        FROM: {FROM_UUID}")
    logger.debug(f"   --->      MSG_ID: {msg_id}")
    logger.info(f"   --->         URL: {url}")
    logger.info(f"   ---> Request XML:\n{xml}")

    logger.info(f"requesting the image")

    async with aiohttp.ClientSession() as session:
        try:
            async with session.post(url, data=xml, headers=headers, timeout=5) as resp:
                if resp.status == 200:
                #    body = await resp.text()
                    body = await resp.read()
                    soap_xml, image_bytes = parse_retrieve_image_response(body, resp.headers.get("Content-Type", ""))
                    if image_bytes:
                        filename = f"/scans/{scanner.friendly_name or scanner_uuid}_{scan_identifier}.jfif"
                        os.makedirs(os.path.dirname(filename), exist_ok=True)
                        with open(filename, "wb") as f:
                            f.write(image_bytes)
                        logger.info(f"[RETRIEVE] Image saved to {filename}")
                        job.state = STATE.SCAN_DONE
                    else:
                        logger.warning(f"[RETRIEVE] No image found in response")
                        job.state = STATE.SCAN_FAIL
                else:
                    SCAN_JOBS[scanjob_identifier].state = STATE.SCAN_FAILED
                    logger.error(f"[SCAN_JOB:rtrv_img] Retrieving image failed with Statuscode {resp.status}")
                    return
        except Exception as e:
            logger.error(f"[SCAN_JOB:rtrv_img] anything went wrong with {SCAN_JOBS[scanjob_identifier]}: {e}")
            SCAN_JOBS[scanjob_identifier].state = STATE.SCAN_FAILED
            return

    logger.info(f"finished reading image from scanner")

#
#
# **************************************************
# *************** END OF SEND.PY ****************
