import asyncio
import datetime
from pathlib import Path
from globals import SCANNERS, SCAN_JOBS, STATE, logger
from tools import save_scanned_image
from send import request_scanner_elements_state, request_scanner_elements_configuration, request_scanner_elements_def_ticket, request_validate_scan_ticket, request_scan_job_ticket, request_retrieve_image

###################################################################################
# Run Scan Job
# ---------------------------------------------------------------------------------
# Parameters:
# job_id = scan job identifier
# ---------------------------------------------------------------------------------
async def run_scan_job(scanjob_identifier: str):
    logger.info(f"{datetime.datetime.now():%Y-%m-%d %H:%M:%S} [SCAN_JOB:run_job] running scan job {scanjob_identifier}")

    await asyncio.sleep(1)                   # Zwangspause für um die Notification erst einmal abzuarbeiten und dann hier nen freien Kopf zu haben.
    logger.debug(f"{datetime.datetime.now():%Y-%m-%d %H:%M:%S} [SCAN_JOB:run_job] short retirement nap is over !")
    
    if scanjob_identifier not in SCAN_JOBS:
        logger.warning(f"could not find any existing job with ID {scanjob_identifier}. Skipping request")
        SCAN_JOBS[scanjob_identifier].state = STATE.SCAN_FAILED   ## das wird fehlschlagen weil es die scanjob-ID ja nicht gibt !!
        return

    # GetScannerElements[State] before requesting a ticket, do nothing while not in IDLE
    SCAN_JOBS[scanjob_identifier].state == STATE.REQ_SCAN_STATE
    result = await request_scanner_elements_state(scanjob_identifier)

    if result:
        logger.info(f" verified that scanner is ready for doing job {scanjob_identifier}")
    else:
        logger.info(f"{datetime.datetime.now():%Y-%m-%d %H:%M:%S} [SCAN_JOB:run_job] seems scanner is busy with anything. What to do now? re-schedule? forget? scan anyways?")
        SCAN_JOBS[scanjob_identifier].state = STATE.SCAN_FAILED
        return

    # GetScannerElements[ScannerConfiguration]
    SCAN_JOBS[scanjob_identifier].state == STATE.REQ_DEF_TICKET
    result = await request_scanner_elements_configuration(scanjob_identifier)

    if result:
        logger.info(f" received valid scanner configuration")
    else:
        logger.info(f"{datetime.datetime.now():%Y-%m-%d %H:%M:%S} [SCAN_JOB:run_job]  something went wrong with requesting the scanners configuration for job {scanjob_identifier}")
        SCAN_JOBS[scanjob_identifier].state = STATE.SCAN_FAILED
        return


    # GetScannerElements[DefaultScanTicket]
    SCAN_JOBS[scanjob_identifier].state == STATE.REQ_DEF_TICKET
    result = await request_scanner_elements_def_ticket(scanjob_identifier)

    if result:
        logger.info(f" received valid default scan ticket")
    else:
        logger.info(f"{datetime.datetime.now():%Y-%m-%d %H:%M:%S} [SCAN_JOB:run_job]  something went wrong with requesting the default scan ticket for job {scanjob_identifier}")
        SCAN_JOBS[scanjob_identifier].state = STATE.SCAN_FAILED
        return

    # ValidateScanTicket Detail
    SCAN_JOBS[scanjob_identifier].state == STATE.REQ_VAL_TICKET
    result = await request_validate_scan_ticket(scanjob_identifier)

    if result:
        logger.info(f" validated scan ticket for {scanjob_identifier}")
    else:
        logger.info(f"{datetime.datetime.now():%Y-%m-%d %H:%M:%S} [SCAN_JOB:run_job]  something went wrong with validating scan ticket for job {scanjob_identifier}")
        SCAN_JOBS[scanjob_identifier].state = STATE.SCAN_FAILED
        return

    # Ticket abholen, Ergebnis wird direkt in SCAN_JOBS[] geschrieben und gibt true für Erfolg, false für Misserfolg zurück
    SCAN_JOBS[scanjob_identifier].state == STATE.SCAN_REQ_TICKET
    result = await request_scan_job_ticket(scanjob_identifier)

    if result:
        logger.info(f" received valid scan job id #{SCAN_JOBS[scanjob_identifier].job_id} and token {SCAN_JOBS[scanjob_identifier].job_token}")
    else:
        logger.info(f"{datetime.datetime.now():%Y-%m-%d %H:%M:%S} [SCAN_JOB:run_job]  something went wrong with requesting a ticket for job {scanjob_identifier}")
        SCAN_JOBS[scanjob_identifier].state = STATE.SCAN_FAILED
        return


    # Bild abholen, Ergebnis wird direkt geparsed und der .document-Anteil in SCAN_JOBS[].document geschrieben. Gibt true für Erfolg, false für Misserfolg zurück
    SCANNERS[SCAN_JOBS[scanjob_identifier].scan_from_uuid].state == STATE.ONLINE_BUSY
    SCAN_JOBS[scanjob_identifier].state == STATE.SCAN_RETRIEVE_IMG
    result = await request_retrieve_image(scanjob_identifier)

    if result:
        logger.info(f" received any {len(SCAN_JOBS[scanjob_identifier].document)} Bytes from {SCANNERS[SCAN_JOBS[scanjob_identifier].scan_from_uuid].friendly_name or SCAN_JOBS[scanjob_identifier].scan_from_uuid}")
        await asyncio.sleep(2)                                        # Zwangspause für um vom Scanner das FIN erst einmal abzuarbeiten und dann gleich nen freien Kopf zu haben.
        logger.debug(f" short retirement nap is over !")
    else:
        logger.info(f"{datetime.datetime.now():%Y-%m-%d %H:%M:%S} [SCAN_JOB:run_job] something went wrong with receiving data from scanner. Document {len(SCAN_JOBS[scanjob_identifier].document)} Bytes ")
        SCAN_JOBS[scanjob_identifier].state = STATE.SCAN_FAILED
        SCANNERS[SCAN_JOBS[scanjob_identifier].scan_from_uuid].state == STATE.ONLINE
        return


    # Bild auf HDD abspeichern
    SCAN_JOBS[scanjob_identifier].state == STATE.SCAN_SAVING_DOCUMENT
    logger.info(f" saving image (more detailed later) from {SCANNERS[SCAN_JOBS[scanjob_identifier].scan_from_uuid].friendly_name or SCAN_JOBS[scanjob_identifier].scan_from_uuid}")
#    result = await save_scanned_image(scanjob_identifier)
    result = save_scanned_image(scanjob_identifier)

    if result:
        logger.info(f" saved image (more detailed later)")
    else:
        logger.info(f"{datetime.datetime.now():%Y-%m-%d %H:%M:%S} [SCAN_JOB:run_job] something went wrong with saving image")
        SCAN_JOBS[scanjob_identifier].state = STATE.SCAN_FAILED
        SCANNERS[SCAN_JOBS[scanjob_identifier].scan_from_uuid].state == STATE.ONLINE
        return


    # alles soweit erledigt
    SCAN_JOBS[scanjob_identifier].job_finished = datetime.datetime.now().replace(microsecond=0)
    SCAN_JOBS[scanjob_identifier].state == STATE.SCAN_DONE
    SCANNERS[SCAN_JOBS[scanjob_identifier].scan_from_uuid].state == STATE.ONLINE
    logger.info(f"{datetime.datetime.now():%Y-%m-%d %H:%M:%S} [SCAN_JOB:run_job] Scan Job done")


#
#
# *****************************************************
# **************** END OF SCAN_JOB.PY  ****************
