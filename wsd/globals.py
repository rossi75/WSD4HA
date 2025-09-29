# to be imported by all files
import logging
import sys
from enum import Enum
import uuid

# -----------------  Logging  -----------------
LOG_LEVEL="ERROR"
LOG_LEVEL="WARNING"
LOG_LEVEL="INFO"
#LOG_LEVEL=DEBUG
#logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')
#logging.basicConfig(level=logging.LOG_LEVEL, format='[%(levelname)s] %(message)s')
logging.basicConfig(level=LOG_LEVEL, format='[%(levelname)s] %(message)s')
logger = logging.getLogger("wsd-addon")

# -----------------  global configuration  -----------------
#OFFLINE_TIMEOUT = int(os.environ.get("OFFLINE_TIMEOUT", 300))  # Sekunden
#SCAN_FOLDER = Path(os.environ.get("SCAN_FOLDER", "/share/scans"))
#SCAN_FOLDER.mkdir(parents=True, exist_ok=True)
#MAX_FILES = int(os.environ.get("MAX_FILES", 5))

# -----------------  define SCANNERS dict  -----------------
SCANNERS = {}

# -----------------  define User-Agent  -----------------
USER_AGENT = "WSD4HA"
#USER_AGENT = "WSDAPI"       # originaler Wert von Microsoft

# -----------------  define FROM_UUID  -----------------
FROM_UUID = None

            
# -----------------  define NAMESPACE  -----------------
NAMESPACES = {
    "df": "http://schemas.microsoft.com/windows/2008/09/devicefoundation",
    "pnpx": "http://schemas.microsoft.com/windows/pnpx/2005/10",
    "sca": "http://schemas.microsoft.com/windows/2006/08/wdp/scan",
    "soap": "http://www.w3.org/2003/05/soap-envelope",
    "ss": "http://www.samsung.com/wsd",
    "wprt": "http://schemas.microsoft.com/windows/2006/08/wdp/print",
    "wsa": "http://schemas.xmlsoap.org/ws/2004/08/addressing",
    "wsd": "http://schemas.xmlsoap.org/ws/2005/04/discovery",
    "wsdp": "http://schemas.xmlsoap.org/ws/2006/02/devprof",
    "wse": "http://schemas.xmlsoap.org/ws/2004/08/eventing",
    "wscn": "http://schemas.microsoft.com/windows/2006/08/wdp/scan",
    "xop": "http://www.w3.org/2004/08/xop/include"
}

# -----------------  define ScannerStati  -----------------
#class ScannerStatus(str, Enum):
class STATE(str, Enum):
    DISCOVERED = "discovered"
    PROBING = "probing"
    PROBE_PARSING = "Probe matched, parsing Probe"
    PROBE_PARSED = "Probe/Match parsed"
    TF_GET_PENDING = "Transfer/Get in progress"
    TF_GET_PARSING = "parsing Transfer/Get"
    TF_GET_PARSED = "Transfer/Get parsed"
    SUBSCRIBING_SCAN_AVAIL_EVT = "Subscribing ScanAvailableEvent"                           # 16
    CHK_SCAN_AVAIL_EVT = "Checking ScanAvailableEvent"
    SUBSCRIBED_SCAN_AVAIL_EVT = "Subscribed ScanAvailableEvent"                             # 18
#    SUBSCRIBING_SCAN_STAT_COND_EVT = "Subscribing ScannerStatusConditionEvent"             # 23
#    CHK_SCAN_STAT_COND_EVT = "Checking ScannerStatusConditionEvent"
#    SUBSCRIBED_SCAN_STAT_COND_EVT = "Subscribed ScannerStatusConditionEvent"               # 24
#    SUBSCRIBING_SCAN_STAT_COND_CLR_EVT = "Subscribing ScannerStatusConditionClearEvent"    # 26
#    CHK_SCAN_STAT_COND_CLR_EVT = "Checking ScannerStatusConditionClearEvent"
#    SUBSCRIBED_SCAN_STAT_COND_CLR_EVT = "Subscribed ScannerStatusConditionClearEvent"      # 27
#    SUBSCRIBING_SCAN_ELEM_CHG_EVT = "Subscribing ScannerElementChangeEvent"                # 29
#    CHK_SCAN_ELEM_CHG_EVT = "Checking ScannerElementChangeEvent"
#    SUBSCRIBED_SCAN_ELEM_CHG_EVT = "Subscribed ScannerElementChangeEvent"                  # 30
#    GET_SCAN_DESCR = "Requesting ScannerDescription"                                       # 31
#    CHK_SCAN_DESCR = "Checking ScannerDescription"
#    DONE_SCAN_DESCR = "Done ScannerDescription"                                            # 33
    GET_DEF_SCAN_TICK = "Requesting DefaultScannerTicket"                                 # 35
    CHK_DEF_SCAN_TICK = "Checking DefaultScannerTicket"
    DONE_DEF_SCAN_TICK = "Done DefaultScannerTicket"                                      # 36
#    GET_SCAN_CONF = "Requesting ScannerConfiguration"                                     # 40
#    CHK_SCAN_CONF = "Checking ScannerConfiguration"
#    DONE_SCAN_CONF = "Done ScannerConfiguration"                                          # 41
    GET_SCAN_STATE = "Requesting ScannerState"                                             # 45
    CHK_SCAN_STATE = "Checking ScannerState"
    DONE_SCAN_STATE = "Done ScannerState"                                                  # 46
    ONLINE = "online"
    ONLINE_CHK_1_2 = "online"                                                              # Hälfte der Zeit is rum
    ONLINE_CHK_3_4 = "online"                                                              # 3/4 der Zeit is rum
    SUBSCR_RNW_1_2_PENDING = "online"                                                      # Hälfte der Zeit is rum
    SUBSCR_RNW_1_2_CHK = "online"                                                          # Hälfte der Zeit is rum
    SUBSCR_RNW_3_4_PENDING = "online"                                                      # 3/4 der Zeit is rum
    SUBSCR_RNW_3_4_CHK = "online"                                                          # 3/4 der Zeit is rum
    RECV_SCAN = "receiving a Scan"
    ABSENT = "absent"
    TO_REMOVE = "to remove"
    ERROR = "error"

# -----------------  Nach jedem Update: Liste loggen  -----------------
def list_scanners():
    logger.info("[SCANNERS] known Scanners:")

    for i, s in enumerate(SCANNERS.values(), start=1):
        logger.info(f"  [{i}] {s.friendly_name or s.uuid} @ {s.ip}")
        logger.debug(f"      --->     XADDR: {s.xaddr}")
        logger.info(f"      --->    Status: {s.state.value}")
        logger.debug(f"      ---> last_seen: {s.last_seen}")
