import asyncio
import datetime
import uuid
import aiohttp
from pathlib import Path
#from globals import SCANNERS, SCAN_JOBS, STATE, WSD_SCAN_FOLDER, MAX_SEMAPHORE, logger
#from globals import SCANNERS, SCAN_JOBS, STATE, SCAN_FOLDER, logger, USER_AGENT
from globals import SCANNERS, SCAN_JOBS, STATE, logger
#from config import OFFLINE_TIMEOUT, LOCAL_IP, HTTP_PORT, USER_AGENT, FROM_UUID, DISPLAY, NOTIFY_PORT
from config import LOCAL_IP, FROM_UUID, DISPLAY, NOTIFY_PORT
from scanner import Scanner, Scan_Jobs
from tools import list_scanners, get_local_ip, save_scanned_image
#from templates import TEMPLATE_SOAP_CREATE_SCANJOB
#from parse import parse_request_scan_job_ticket
from send import request_scan_job_ticket, request_retrieve_image

#import logging
#import os
#import re
#import socket
#import subprocess
#import sys
#import time
#import threading
#import xml.etree.ElementTree as ET

#from config import OFFLINE_TIMEOUT, LOCAL_IP, HTTP_PORT, FROM_UUID, DISPLAY, NOTIFY_PORT, get_local_ip
#from globals import SCANNERS, list_scanners, NAMESPACES, STATE, USER_AGENT, LOG_LEVEL
#from globals import SCANNERS, SCAN_JOBS, NAMESPACES, SCAN_FOLDER, STATE, USER_AGENT, LOG_LEVEL
#from parse import parse_wsd_packet, parse_probe, parse_transfer_get, parse_subscribe

#    SCAN_REQ_TICKET = "Requesting Job Ticket"
#    SCAN_RETRIEVING = "receiving/downloading a Document"
#    SCAN_DONE = "Document scan done successfully"
#    SCAN_FAILED = "Document scan failed"


#WSD_SCAN_FOLDER.mkdir(parents=True, exist_ok=True)
#SEMAPHORE = asyncio.Semaphore(MAX_SEMAPHORE)   # max parallel downloads

###################################################################################
# Run Scan Job
# ---------------------------------------------------------------------------------
# Parameters:
# job_id = scan job identifier
# ---------------------------------------------------------------------------------
#async def run_scan_job(job_id: str):
async def run_scan_job(scanjob_identifier: str):
    logger.info(f"{datetime.datetime.now():%Y-%m-%d %H:%M:%S} [SCAN_JOB:run_job] running scan job {scanjob_identifier}")

    await asyncio.sleep(2)                   # Zwangspause für um die Notification erst einmal abzuarbeiten und dann hier nen freien Kopf zu haben.
    logger.info(f"{datetime.datetime.now():%Y-%m-%d %H:%M:%S} [SCAN_JOB:run_job] weiter geht's !")
    
    if scan_identifier not in SCAN_JOBS:
        logger.warning(f"could not find any existing job with ID {scanjob_identifier}. Skipping request")
        SCAN_JOBS[scanjob_identifier].status = STATE.SCAN_FAILED
        return
#    else:
#        if SCAN_JOBS[scan_identifier].status == STATE.SCAN_PENDING:
#            SCAN_JOBS[scan_identifier].status == STATE.SCAN_REQ_TICKET

#    scanner_uuid = SCAN_JOBS[scan_identifier].scan_from_uuid

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


    # Ticket abholen, Ergebnis wird direkt in SCAN_JOBS[] geschrieben und gibt true für Erfolg, false für Misserfolg zurück
    SCAN_JOBS[scanjob_identifier].status == STATE.SCAN_REQ_TICKET
    result = asyncio.create_task(request_scan_job_ticket(scanjob_identifier))

    if result:
        logger.info(f" received scan job id #{SCAN_JOBS[scanjob_identifier].job_id} and token {SCAN_JOBS[scanjob_identifier].job_token}")
    else:
        logger.info(f" something went wrong with requesting a ticket for job {scanjob_identifier}")
        SCAN_JOBS[scanjob_identifier].status = STATE.SCAN_FAILED
        return


    # Bild abholen, Ergebnis wird direkt in SCAN_JOBS[] geschrieben und gibt true für Erfolg, false für Misserfolg zurück
    SCAN_JOBS[scanjob_identifier].status == STATE.SCAN_RETRIEVING
    result = asyncio.create_task(request_retrieve_image(scanjob_identifier))

    if result:
        logger.info(f" received data from scanner (more detailed later)")
    else:
        logger.info(f" something went wrong with receiving data from scanner")
        SCAN_JOBS[scanjob_identifier].status = STATE.SCAN_FAILED
        return


    # Bild auf HDD abspeichern
    SCAN_JOBS[scanjob_identifier].status == STATE.SCAN_SAVING
    result = save_scanned_image({SCANNERS[SCAN_JOBS[scanjob_identifier].scan_from_uuid].friendly_name or SCAN_JOBS[scanjob_identifier].scan_from_uuid}, result):

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
