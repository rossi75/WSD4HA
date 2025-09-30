# Changelog

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
