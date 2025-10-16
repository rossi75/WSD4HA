# WSD4HA
provides a simple WSD protocol for scanning documents into homeassistants file system


## **!! actually in development !!**

Creating a WSD service in Home Assistant for my Samsung C480W.
So any documents can always be scanned to the anyways and always running server. Afterwards those documents can be processed from any OCR software like paperless or so. Maybe other ~printers~ scanners are working too?

If WSD4HA is being restarted, the scanner needs to be restarted also ! This is due to the fact that the scanner (C480W) sends out its discovery message only once (technically twice) directly after booting. WSD4HA only supports IPv4

## Where is your scanner?
If you want to get added a specific MFD, leave me a wireshark from your windows (!) 7/8/10/11. It may be filtered for your scanners IP and must contain
- the scanners booting process (for registration)
- half an hour later (for subscription renewal)
- scanning a document (for retrieval processing)

## What else?
Sadly, all options that can be seen in the configurations dialog, are non-functional at the moment... (seems I need some help at this point)
