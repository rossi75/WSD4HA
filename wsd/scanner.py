import datetime
from config import OFFLINE_TIMEOUT
from datetime import timedelta
from globals import SCANNERS, NAMESPACES, STATE, logger
from tools import list_scanners, marry_endpoints

# ---------------- Scanner-Datenstruktur ----------------
class Scanner:
    def __init__(self, uuid, ip = "0.0.0.0", xaddr = None):
        logger.debug(f"{datetime.datetime.now():%Y-%m-%d %H:%M:%S} [SCANNER:__init__] New instance of Scanner")
        self.uuid = uuid
        self.ip = ip

        # WSD Parameters
        self.xaddr = xaddr            # Service-Adresse (aus <wsd:XAddrs>)
        self.subscription_timeout = 0
        self.subscription_last_seen = None
        self.subscription_id = None
        self.subscription_ref = None
        self.destination_token = None
        self.end_to_addr = None

        # zusätzliche optionale Infos
        self.friendly_name = None
        self.mac = None
        self.firmware = None
        self.serial = None
        self.model = None
        self.manufacturer = None
        self.related_uuids = set()
        self.ScanTicket_Dialect = None              # SIMPLE or DETAIL

        # Status
        self.first_seen = datetime.datetime.now().replace(microsecond=0)
        self.last_seen = datetime.datetime.now().replace(microsecond=0)
        self.state = STATE.DISCOVERED
        self.offline_since = None
        self.remove_after = None  # Zeitpunkt zum Löschen

        logger.debug(f"   --->  UUID: {self.uuid}")
        logger.debug(f"   --->    IP: {self.ip}")
        logger.debug(f"   ---> XADDR: {self.xaddr}")

    # Scanner ist noch online
    # Aufruf mit SCANNER[uuid].update()
    def update(self):
        self.last_seen = datetime.datetime.now().replace(microsecond=0)
        self.state = STATE.ONLINE
        self.offline_since = None
        self.remove_after = None

        logger.info(f"{datetime.datetime.now():%Y-%m-%d %H:%M:%S} [SCANNER:upd] Updated timestamps for {self.friendly_name} @ {self.ip} with UUID {self.uuid}")
        logger.debug(f"   ---> new last_seen: {self.last_seen}")

    # Scannerservice ist noch online
    # Aufruf mit SCANNER[uuid].update_subscription()
    def update_subscription(self):
        self.subscription_last_seen = datetime.datetime.now().replace(microsecond=0)
        self.last_seen = datetime.datetime.now().replace(microsecond=0)
        self.state = STATE.ONLINE
        self.offline_since = None
        self.remove_after = None
        logger.info(f"{datetime.datetime.now():%Y-%m-%d %H:%M:%S} [SCANNER:upd_subscr] Updated timestamps for scanner subscription {self.friendly_name} @ {self.ip} with UUID {self.uuid}")
        logger.info(f"   ---> new subscribtion last_seen: {self.subscription_last_seen}")

    # wird aufgerufen wenn ein Scanner offline gesetzt wird
    # Aufruf mit SCANNER[uuid].mark_offline()
    def mark_absent(self):
        self.state = STATE.ABSENT
        if not self.offline_since:
            self.offline_since = datetime.datetime.now().replace(microsecond=0)
            self.remove_after = self.offline_since + datetime.timedelta(seconds=OFFLINE_TIMEOUT)
        logger.info(f"{datetime.datetime.now():%Y-%m-%d %H:%M:%S} [SCANNER:m_offl] marked {self.friendly_name} @ {self.ip} as offline")
        logger.debug(f"   -->         state: {self.state}")
        logger.debug(f"   --> offline_since: {self.offline_since}")
        logger.debug(f"   -->  remove_after: {self.remove_after}")

# ---------------- ScanJob-Datenstruktur ----------------
class Scan_Jobs:
    def __init__(self, scan_job_idendtifier, scan_from_uuid, input_source):
        logger.debug(f"{datetime.datetime.now():%Y-%m-%d %H:%M:%S} [SCAN_JOBS:__init__] New instance of a Scan Job")

        self.scanjob_identifier = scan_job_idendtifier
        self.job_id = None
        self.job_token = None
        self.input_source = input_source
        self.scan_from_uuid = scan_from_uuid
        self.subscription_identifier = SCANNERS[scan_from_uuid].subscription_id
        self.xaddr = SCANNERS[scan_from_uuid].xaddr
        self.destination_token = SCANNERS[scan_from_uuid].destination_token

        self.state = STATE.SCAN_PENDING
        self.job_created = datetime.datetime.now().replace(microsecond=0)
        self.job_finished = None
        self.remove_after = datetime.datetime.now().replace(microsecond=0) + timedelta(minutes=30) # Zeitpunkt zum Löschen des Auftrages = jetzt + 30 Minuten
        SCANNERS[scan_from_uuid].update()

        # Document related parameters
        self.DocPar_FileFormat = 'jfif'
        self.DocPar_ImagesToTransfer = 1
        self.DocPar_InputSource = None
        self.DocPar_InputWidth = None
        self.DocPar_InputHeight = None
        self.DocPar_ResolutionWidth = None
        self.DocPar_ResolutionHeight = None
        self.DocPar_ExposureContrast = 0
        self.DocPar_ExposureBrightness = 0
        self.DocPar_ScalingWidth = 100
        self.DocPar_ScalingHeight = 100
        self.DocPar_Rotation = 0
        self.DocPar_RegionXOffset = 0
        self.DocPar_RegionYOffset = 0
        self.DocPar_RegionWidth = None
        self.DocPar_RegionHeight = None
        self.DocPar_ColorProcessing = 'RGB24'
        self.DocPar_PixelsPerLine = None
        self.DocPar_NumberOfLines = None
        self.DocPar_BytesPerLine = None

        self.document = ""                                                  # hier kommt das eigentliche Dokument hin
        self.filepath = ""                                                  # und hier wird/wurde es auf die Floppy geschrieben

        logger.info(f"   --->    SCAN_JOB_ID: {self.scanjob_identifier}")
        logger.debug(f"   --->          STATE: {self.state.value}")
        logger.debug(f"   --->   INPUT_SOURCE: {self.input_source}")
        logger.debug(f"   ---> SCAN FROM UUID: {self.scan_from_uuid}")
        logger.debug(f"   --->      SUBSCR_ID: {self.subscription_identifier}")
        logger.debug(f"   --->          XADDR: {self.xaddr}")
        logger.debug(f"   --->     DEST_TOKEN: {self.destination_token}")
        logger.debug(f"   --->         STATUS: {self.state}")
        logger.debug(f"   --->        CREATED: {self.job_created}")
        logger.debug(f"   --->   REMOVE_AFTER: {self.remove_after}")


#
#
# **************************************************
# *************** END OF SCANNER.PY ****************
