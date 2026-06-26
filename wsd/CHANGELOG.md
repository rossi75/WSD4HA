# Changelog

## 0.79 - 2026-06-25
- fixed a bug where a pinned scanner was removed from the UIs list (and internally also), after a pinned scanner was switched off. After restarting the add-on, everything worked fine again, so the storage was not written
- changed page renew delay from 2 seconds to 1 second after un-/pinning
- improved texts for subscription check
- name change adopts file extension if not given

## 0.78 - 2026-06-19
- added rename button in UI

## 0.77 - 2026-06-11
- fixed issue if you have multiple scanners, only the last one was shown
- fixed issue #1 where the service stops randomly
- changed logging output for known scanners, added pinned-state

## 0.76 - 2026-06-09
- improved Pin/Unpin Action
- direct download from filename
- if scanner is pinned, probing every 20 seconds instead of every single second

## 0.75 - 2026-06-07
- added new option to permanently add this scanner to the list. After an application (WSD4HA/Home Assistant) restart, the scanner is being contacted by WSD4HA itself. So the scanner does not need to be rebooted to receive its initial packets  
  First column + means you can add this scanner to the list, - means you can delete this from the list. You can find all permanent added scanners in /share/wsd4ha/pinned_scanners.json

## 0.74 - 2026-05-29
- save documents to floppy disk worked only within its container, now in the Hosts filesystem
- new filepath is /share/wsd4ha/scans, scanned documents persist any restarts now
- document download button in GUI
- document delete button in GUI
- documents sorted by D/T
- GUI Auto-Reload all 60 seconds

## 0.73 - 2025-10-16
- added probe exceptions
- save to floppy disk works fine

## 0.72 - 2025-10-16
- extracting data works, saving into SCAN_JOBS[].document. Now we need to save it to the floppy disk

## 0.70 - 2025-10-15
- SCAN_JOBS[].job_finished + .filepath

## 0.69 - 2025-10-15
- receiving the data works, now we need to extract it and save it into SCAN_JOBS[].document
- nice banner at startup

## 0.68 - 2025-10-15
- scan to HA works, the scanner moves...

## 0.65 - 2025-10-14
- implement GetScannerElements[State] before requesting a ticket, do nothing while not in IDLE
- implement GetScannerElements[ScannerConfiguration] only for MaxWidth and MaxHeight into RegionW/R and ...?

## 0.63 - 2025-10-14
- implement detailed variant of ValidateScanTicket
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
- hold scanners in memory after any reboot, retry after reboot and every x seconds if not online
