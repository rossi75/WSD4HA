# WSD4HA

provides a simple WSD protocol for scanning documents into homeassistants file system

Creating a WSD service in Home Assistant for my Samsung C480W.
So any documents can always be scanned to the anyways and always running server. The files are saved into /share/wsd4ha/scans/. Afterwards those documents can be downloaded or processed from any OCR software like paperless or so. Maybe other ~printers~ scanners are working too?

If WSD4HA (or HomeAssistant) is being restarted, it looses its knowledge about any available scanners that are online. This is due to the fact that the (my!) scanner (C480W) sends out its discovery message only once (technically twice) directly after booting. With version 0.75 I introduced a pinned_scanners.json, which will be read at startup. Any scanner added to this list will be contacted after restart.
WSD4HA only supports IPv4

## Tested/confirmed scanners
- Samsung C480W
- Samsung C460FW

## Where is YOUR scanner?
If you want to get added a specific MFD, leave me a wireshark from your windows (!) 7/8/10/11. It may be filtered for your scanners IP and must contain
- the scanners booting process (for registration)
- half an hour later (for subscription renewal)
- scanning a document (for retrieval processing)

## What else?
Sadly, all options that can be seen in the configurations dialog, are non-functional at the moment... (seems I need some help at this point)

## Installation
Go to Settings/Apps, click on "Install App", you will see the App Store. In the three dots menu (upper right) choose "Repositories". Hence you click on "Add" once again and enter "https://github.com/rossi75/WSD4HA".
Go back to the App Store and search for "WSD4HA". Open it and you will see an "Install" button which you may click.

## open topics / todo
- make manual configuration functional
- implement simple variant of ValidateScanTicket
- decide automatically between simple and detailled variant of ValidateScanTicket
- implement GetScannerElements[ScannerDescription]
- merge globals.py + config.py to globalconfig.py
- add WSD secure (Port 5358)
- webinterface improvements:
  - left column for tree with config_output/scanners/jobs/scans
  - display several details only in debug mode
  - mouseover for tech details
  - scan from UI
... 


