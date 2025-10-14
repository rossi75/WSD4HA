import asyncio
import datetime
from pathlib import Path
from globals import SCANNERS, SCAN_JOBS, STATE, logger
from scanner import Scanner, Scan_Jobs
from tools import save_scanned_image
from send import request_scanner_elements_state, request_scanner_elements_def_ticket, request_validate_scan_ticket, request_scan_job_ticket, request_retrieve_image

###################################################################################
# Run Scan Job
# ---------------------------------------------------------------------------------
# Parameters:
# job_id = scan job identifier
# ---------------------------------------------------------------------------------
async def run_scan_job(scanjob_identifier: str):
    logger.info(f"{datetime.datetime.now():%Y-%m-%d %H:%M:%S} [SCAN_JOB:run_job] running scan job {scanjob_identifier}")

    await asyncio.sleep(2)                   # Zwangspause für um die Notification erst einmal abzuarbeiten und dann hier nen freien Kopf zu haben.
    logger.info(f"{datetime.datetime.now():%Y-%m-%d %H:%M:%S} [SCAN_JOB:run_job] short retirement nap is over !")
    
    if scanjob_identifier not in SCAN_JOBS:
        logger.warning(f"could not find any existing job with ID {scanjob_identifier}. Skipping request")
        SCAN_JOBS[scanjob_identifier].status = STATE.SCAN_FAILED   ## das wird fehlschlagen weil es die scanjob-ID ja nicht gibt !!
        return

    # GetScannerElements[State] before requesting a ticket, do nothing while not in IDLE
    SCAN_JOBS[scanjob_identifier].status == STATE.REQ_SCAN_STATE
    result = await request_scanner_elements_state(scanjob_identifier)

    if result:
        logger.info(f" verified that scanner is ready for doing job #{scanjob_identifier}")
    else:
        logger.info(f" seems scanner is busy with anything. What to do now? re-schedule? forget? scan anyways?")
        SCAN_JOBS[scanjob_identifier].status = STATE.SCAN_FAILED
        return

    # GetScannerElements[DefaultScanTicket]
    SCAN_JOBS[scanjob_identifier].status == STATE.REQ_DEF_TICKET
    result = await request_scanner_elements_scanner_configuration(scanjob_identifier)

    if result:
        logger.info(f" received valid scanner configuration")
    else:
        logger.info(f" something went wrong with requesting the scanners configuration for job {scanjob_identifier}")
        SCAN_JOBS[scanjob_identifier].status = STATE.SCAN_FAILED
        return


    # GetScannerElements[DefaultScanTicket]
    SCAN_JOBS[scanjob_identifier].status == STATE.REQ_DEF_TICKET
    result = await request_scanner_elements_def_ticket(scanjob_identifier)

    if result:
        logger.info(f" received valid default scan ticket")
    else:
        logger.info(f" something went wrong with requesting the default scan ticket for job {scanjob_identifier}")
        SCAN_JOBS[scanjob_identifier].status = STATE.SCAN_FAILED
        return

    # ValidateScanTicket Detail
    SCAN_JOBS[scanjob_identifier].status == STATE.REQ_VAL_TICKET
    result = await request_validate_scan_ticket(scanjob_identifier)

    if result:
        logger.info(f" validated scan ticket for {scanjob_identifier}")
    else:
        logger.info(f" something went wrong with validating scan ticket for job {scanjob_identifier}")
        SCAN_JOBS[scanjob_identifier].status = STATE.SCAN_FAILED
        return

    # Ticket abholen, Ergebnis wird direkt in SCAN_JOBS[] geschrieben und gibt true für Erfolg, false für Misserfolg zurück
    SCAN_JOBS[scanjob_identifier].status == STATE.SCAN_REQ_TICKET
    result = await request_scan_job_ticket(scanjob_identifier)

    if result:
        logger.info(f" received scan job id #{SCAN_JOBS[scanjob_identifier].job_id} and token {SCAN_JOBS[scanjob_identifier].job_token}")
    else:
        logger.info(f" something went wrong with requesting a ticket for job {scanjob_identifier}")
        SCAN_JOBS[scanjob_identifier].status = STATE.SCAN_FAILED
        return


    # Bild abholen, Ergebnis wird direkt in SCAN_JOBS[] geschrieben und gibt true für Erfolg, false für Misserfolg zurück
    SCAN_JOBS[scanjob_identifier].status == STATE.SCAN_RETRIEVE_IMG
    result = asyncio.create_task(request_retrieve_image(scanjob_identifier))

    if result:
        logger.info(f" received data from scanner (more detailed later)")
    else:
        logger.info(f" something went wrong with receiving data from scanner")
        SCAN_JOBS[scanjob_identifier].status = STATE.SCAN_FAILED
        return


    # Bild auf HDD abspeichern
    SCAN_JOBS[scanjob_identifier].status == STATE.SCAN_SAVING
    result = save_scanned_image({SCANNERS[SCAN_JOBS[scanjob_identifier].scan_from_uuid].friendly_name or SCAN_JOBS[scanjob_identifier].scan_from_uuid}, result)

    if result:
        logger.info(f" saved  image (more detailed later)")
    else:
        logger.info(f"{datetime.datetime.now():%Y-%m-%d %H:%M:%S} [SCAN_JOB:run_job] something went wrong with saving image")
        SCAN_JOBS[scanjob_identifier].status = STATE.SCAN_FAILED
        return


    # alles soweit erledigt
    logger.info(f"{datetime.datetime.now():%Y-%m-%d %H:%M:%S} [SCAN_JOB:run_job] Scan Job done")
    SCAN_JOBS[scanjob_identifier].status == STATE.SCAN_DONE


#
#
# *****************************************************
# **************** END OF SCAN_JOB.PY  ****************
