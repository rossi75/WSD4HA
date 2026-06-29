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

## Issue with parallel SAMBA App
If you have installed the SAMBA App parallel to WSD4HA, there will be some issue. Since version 12.7.0 there is a WSDD service for Windows that shows up the HA instance as a network drive. This WSDD service occupies the WSD port 5357, which this App will also use.
Already pinned Scanners will work fine, new scanners will only be detected if at their boot-up the Samba App was not running.

If you experience any issues with this, you need to disable SAMBA, restart WSD4HA, enable SAMBA again. Hence both indicators should show green:  
<img width="163" height="45" alt="grafik" src="https://github.com/user-attachments/assets/05af0df8-4322-4c89-ad0f-b0eb7b14ab37" />

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


