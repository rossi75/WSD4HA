# 07.06.2026: Please do NOT UPDATE today

# WSD4HA
provides a simple WSD protocol for scanning documents into homeassistants file system

Creating a WSD service in Home Assistant for my Samsung C480W.
So any documents can always be scanned to the anyways and always running server. The files are saved into /share/wsd4ha/scans/. Afterwards those documents can be processed from any OCR software like paperless or so. Maybe other ~printers~ scanners are working too?

If WSD4HA is being restarted, the scanner needs to be restarted also ! This is due to the fact that the (my!) scanner (C480W) sends out its discovery message only once (technically twice) directly after booting. WSD4HA only supports IPv4

## Where is YOUR scanner?
If you want to get added a specific MFD, leave me a wireshark from your windows (!) 7/8/10/11. It may be filtered for your scanners IP and must contain
- the scanners booting process (for registration)
- half an hour later (for subscription renewal)
- scanning a document (for retrieval processing)

## What else?
Sadly, all options that can be seen in the configurations dialog, are non-functional at the moment... (seems I need some help at this point)

## open topics / todo
- make manual configuration functional
- implement simple variant of ValidateScanTicket
- decide automatically between simple and detailled variant of ValdiateScanTicket
- implement GetScannerElements[ScannerDescription]
- merge globals.py + config.py to globalconfig.py
- add WSD secure (Port 5358)
- webinterface improvements:
  - left column for tree with config_output/scanners/jobs/scans
  - display several details only in debug mode
  - mouseover for tech details
  - scan from UI
  - save scanner in a permanent list
  - subscribe permanent devices from UI

... 

