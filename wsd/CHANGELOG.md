# Changelog

### todo
- make manual configuration functional
- implement detailled variant of ValdiateScanTicket
- implement simple variant of ValdiateScanTicket
- decide automatically between simple and detailled variant of ValdiateScanTicket
- implement GetScannerElements[ScannerDescription]
- implement GetScannerElements[ScannerConfiguration]
- write bin to harddisk
- merge globals.py + config.py to globalconfig.py
- webinterface improvements:
  - left column for tree with config_output/scanners/jobs/scans
  - display several details only in debug mode
  - download files
- ...

## 0.65 - 2025-10-14
- implement GetScannerElements[State] before requesting a ticket, do nothing while not in IDLE

## 0.63 - 2025-10-14
- implement GetScannerElements[DefaultScanTicket]
- SCANNERS[].serial and SCANNERS[].model are now parsed correctly

## 0.61 - 2025-10-12
- filled scan_job.py with live
- implement CreateScanJob[CreateScanJobRequest]
- import logger for all files from globals.py
 
## 0.60 - 2025-10-10
- creating/requesting ticket for a scan job after notification
- SCAN_JOBS[] now stores the outstanding jobs

## 0.57 - 2025-10-07
- outsourced many helper functions into new tools.py

## 0.56 - 2025-09-29
- solved subscription renew issue

## 0.54 - 2025-09-29
- added routine for receiving scanner ticket
- display entry works now, needed to put the name and xml within one line
- Heartbeat for online state and subscribing state

## 0.18.51 - 2025-09-26
- added complete subscribing renew routine with several new states
! sending subscribing renew works, but returns a 500 server internal error from the scanner

## 0.18.x - 2025-09-24
- port 5357 should be available for notifications
- subscribed for scan events
- new indexing, 0.xx.y, where xx reflects the packet number from the referenced pcap

## 0.0.3_ – 2025-09-11
- change weather

## 0.0.3 – 2025-09-11
- 🆕 added Scanner-Heartbeat via probe
- port readout stuck

## 0.0.2 – 2025-09-08
- 🔧 ignoring IPv6, if IPv4 is available
- 📦 multiple files (main.py, scanner.py, wsd.py, global.py, ...)

## 0.0.1 – 2025-09-01
- Erste Version mit WSD-Discovery (Hello/Bye)
- Logging für Scanner-Events implementiert

---
# ToDo:
- Scan receive
- Parameter from HA-/Docker-Config to PY
