import asyncio
import datetime
import os
import socket
import subprocess
import sys
import time
import threading
import uuid
import xml.etree.ElementTree as ET
from config import OFFLINE_TIMEOUT, FROM_UUID
#from globals import LISTENING_UDP_3702_WSD, SCANNERS, SCAN_JOBS, NAMESPACES, STATE, logger
import globals
from pathlib import Path
from scanner import Scanner
from send import send_probe, send_transfer_get, send_subscription_ScanAvailableEvent, send_subscription_renew
from tools import list_scanners, pick_best_xaddr

# ---------------- Message handler ----------------
async def discovery_processor(data, addr):
    globals.logger.info(f"{datetime.datetime.now():%Y-%m-%d %H:%M:%S} [WSD:Disc_Proc] Processing something from {addr[0]}")
    globals.logger.debug(f"   ---> received addr: {addr}")
    globals.logger.debug(f"   ---> received data:\n{data}")

    ip = addr[0] if addr else "?"

    try:
        root = ET.fromstring(data.decode("utf-8", errors="ignore"))
    except Exception:
        globals.logger.error("[WSD:dp] Exception while reading from ET")
        return

    # UUID (without urn:uuid:)
    uuid_raw = root.find(".//wsa:Address", globals.NAMESPACES)
    uuid = None
    if uuid_raw is not None and uuid_raw.text:
        uuid_text = uuid_raw.text.strip()
        if uuid_text.startswith("urn:uuid:"):
            uuid = uuid_text.replace("urn:uuid:", "")
        else:
            uuid = uuid_text

    # extract Action
    action_elem = root.find(".//wsa:Action", globals.NAMESPACES)
    action_text = None
    if action_elem is not None and action_elem.text:
        action_text = action_elem.text.split("/")[-1]  # → "Hello|Bye|Probe"

    # extract Device Capability        
    types_elem = root.find(".//wsd:Types", globals.NAMESPACES)
    types_text = ""
    if types_elem is not None and types_elem.text:
        # Zerlegen + Präfixe entfernen
        types_text = " ".join(t.split(":")[-1] for t in types_elem.text.split())

    # exctract XAddrs
    xaddrs_elem = root.find(".//wsd:XAddrs", globals.NAMESPACES)
    xaddr = ""
    if xaddrs_elem is not None and xaddrs_elem.text:
        xaddr = pick_best_xaddr(xaddrs_elem.text.strip())

    globals.logger.debug(f"    --->   UUID: {uuid}")
    globals.logger.info(f"    ---> Action: {action_text}")
    globals.logger.debug(f"    --->  Types: {types_text}")
    globals.logger.debug(f"    --->  XADDR: {xaddr}")

    if action_text == "Hello":
        # Nur Scanner berücksichtigen
        if "ScanDeviceType" not in types_text:
            globals.logger.info(f"[WSD:HELLO] Ignored non-scanner device UUID={uuid} Types={types_text}")
            return

        if uuid not in globals.SCANNERS:
            globals.SCANNERS[uuid] = Scanner(uuid=uuid, ip=ip, xaddr=xaddr)
            logger.info(f"[WSD:HELLO] New Scanner: {globals.SCANNERS[uuid].uuid} ({ip})")
        else:
#            if SCANNERS[uuid].state.value == "online":
#                SCANNERS[uuid].update()
#            logger.info(f"[WSD:HELLO] known Scanner seen again: {SCANNERS[uuid].friendly_name} ({ip})")


            # Bereits vorhandenen Scanner aktualisieren
            s = globals.SCANNERS[uuid]
    
            s.ip = ip
            s.xaddr = xaddr
            s.last_seen = datetime.datetime.now()
    
            # Falls der Scanner nur aus der Persistenz geladen wurde
            if s.state == globals.STATE.PINNED:
                globals.logger.info(f"[WSD:HELLO] Pinned scanner '{s.friendly_name}' is now online.")
                s.state = globals.STATE.ONLINE
            else:
                s.update()
    
            globals.logger.info(f"[WSD:HELLO] Known scanner seen again: {s.friendly_name} ({ip})")
        list_scanners()

    elif action_text == "Bye":
        globals.logger.info(f"[WSD:BYE] Bye for uuid: {uuid}")
        if uuid in globals.SCANNERS:
            if globals.SCANNERS[uuid].pinned is True:
                globals.logger.info(f"[WSD:BYE] Scanner has gone, but needs to stay known because it is pinned: {globals.SCANNERS[uuid].friendly_name} ({ip})")
            else:
                globals.logger.warning(f"[WSD:BYE] Scanner has gone, deleting: {globals.SCANNERS[uuid].friendly_name} ({ip})")
                del globals.SCANNERS[uuid]
        list_scanners()
    else:
        globals.logger.warning(f"[WSD:Message] received unrecognized operation {action_text} from {ip}")

    globals.logger.debug(f"[WSD:Message] done")


# ---------------- UDP listener ----------------
async def UDP_listener_3702():
    # WSD (Port 3702/UDP)
    MCAST_GRP = "239.255.255.250"
    MCAST_PORT = 3702

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("", MCAST_PORT))
        mreq = socket.inet_aton(MCAST_GRP) + socket.inet_aton("0.0.0.0")
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
        sock.setblocking(False)   # WICHTIG für asyncio!
        globals.logger.info("WSD-Listener running on Port 3702/UDP")
        globals.LISTENING_UDP_3702_WSD = True
    except Exception as e:
        globals.LISTENING_UDP_3702_WSD = False
        globals.logger.warning(f"Could not bind UDP/3702: {e}")
        return

    # Daten abholen
    loop = asyncio.get_running_loop()
    async def recv_loop():
        while True:
            globals.logger.debug(f"{datetime.datetime.now():%Y-%m-%d %H:%M:%S} [WSD:recv_loop] waiting for UDP data")
            data, addr = await loop.sock_recvfrom(sock, 8192)
            await discovery_processor(data, addr)   # ausgelagerte Verarbeitung
            await asyncio.sleep(1)

    await recv_loop()

# ---------------- Scanner Probe ----------------
async def state_monitor():
    while True:
        logger.debug(f"{datetime.datetime.now():%Y-%m-%d %H:%M:%S} [WSD:state_mon] wake-up")
        to_remove = []
        now = datetime.datetime.now().replace(microsecond=0)
        subscr_age = 0

        for uuid, scanner in globals.SCANNERS.items():
            logger.info(f"{datetime.datetime.now():%Y-%m-%d %H:%M:%S} [WSD:state_mon] Checking State and Timer for {scanner.friendly_name} @ {scanner.ip}...")
            status = scanner.state.value
            age = (now - scanner.last_seen).total_seconds()
            logger.info(f"   --->            state: {status} ({scanner.state})")
            logger.debug(f"   --->       first_seen: {scanner.first_seen}")
            logger.info(f"   --->        last_seen: {scanner.last_seen}          age: {age} seconds old")
            if scanner.subscription_last_seen is not None:
                subscr_age = (now - scanner.subscription_last_seen).total_seconds()
                logger.info(f"   ---> subscr_last_seen: {scanner.subscription_last_seen}          age: {subscr_age} seconds old")
            
            if scanner.state.value in "online":          # auch die Sub-Stati für renew haben "online" als value
                # 3/4-Check for subscription
                if subscr_age >= (globals.SCANNERS[uuid].subscription_timeout * 0.75):
                    scanner.state = globals.STATE.SUBSCR_RNW_3_4_PENDING
                    logger.warning(f"[WSD:Heartbeat] ---> proceeding 3/4-Check for Subscription")
                    try:
                        asyncio.create_task(send_subscription_renew(uuid))                # update_subscription() später im parser
                    except Exception as e:
                        scanner.state = globals.STATE.ABSENT
                        logger.warning(f"{datetime.datetime.now():%Y-%m-%d %H:%M:%S} Could not reach scanner {scanner.friendly_name} @ {scanner.ip}. Last subscription at {scanner.subscription_last_seen}. Response is {str(e)}")

                # Halbzeit-Check for subscription
                elif subscr_age >= (globals.SCANNERS[uuid].subscription_timeout / 2):
                    scanner.state = globals.STATE.SUBSCR_RNW_1_2_PENDING
                    logger.info(f"[WSD:Heartbeat] ---> proceeding Halftime-Check for Subscription")
                    try:
                        asyncio.create_task(send_subscription_renew(uuid))                # update_subscription() später im parser
                    except Exception as e:
                        logger.warning(f"{datetime.datetime.now():%Y-%m-%d %H:%M:%S} Could not reach scanner {scanner.friendly_name} @ {scanner.ip}. Last subscription at {scanner.subscription_last_seen}. Response is {str(e)}")

                # 3/4-Check Online
                elif age >= (OFFLINE_TIMEOUT * 0.75):
                    logger.warning(f"[WSD:Heartbeat] ---> proceeding 3/4-Check")
                    try:
                        asyncio.create_task(send_probe(uuid))
                    except Exception as e:
                        logger.warning(f"{datetime.datetime.now():%Y-%m-%d %H:%M:%S} Could not reach scanner {scanner.friendly_name} @ {scanner.ip}. Last seen at {scanner.last_seen}. Response is {str(e)}")

                # Halbzeit-Check Online
                elif age >= (OFFLINE_TIMEOUT / 2):
                    logger.info(f"[WSD:Heartbeat] ---> proceeding Halftime-Check")
                    try:
                        asyncio.create_task(send_probe(uuid))
                    except Exception as e:
                        logger.warning(f"{datetime.datetime.now():%Y-%m-%d %H:%M:%S} Could not reach scanner with {scanner.friendly_name} @ {scanner.ip}. Last seen at {scanner.last_seen}. Response is {str(e)}")
    
            if scanner.state in globals.STATE.TF_GET_PARSED:
                logger.info(f"[WSD:state_mon] Transfer/Get parsed, subscribing to EP...")
                try:
                    asyncio.create_task(send_subscription_ScanAvailableEvent(uuid))
                except Exception as e:
                    scanner.state = globals.STATE.ERROR
                    logger.warning(f"Anything went wrong while parsing the subscribe attempt from {scanner.friendly_name} @ {scanner.ip}, response is {str(e)}")

            if scanner.state in globals.STATE.PROBE_PARSED:
                logger.info(f"[WSD:state_mon] probe parsed, get endpoint details...")
                try:
                    asyncio.create_task(send_transfer_get(uuid))
                except Exception as e:
                    scanner.state = globals.STATE.ERROR
                    logger.warning(f"Anything went wrong while parsing the XML-Probe from {scanner.friendly_name} @ {scanner.ip}, response is {str(e)}")

            if scanner.state in globals.STATE.PINNED:
                logger.info(f"[WSD:state_mon] Fresh loaded from pinning, now probing...")
                try:
                    asyncio.create_task(send_probe(uuid))
                except Exception as e:
                    scanner.state = globals.STATE.ERROR
                    logger.warning(f"Anything went wrong while probing {scanner.friendly_name} @ {scanner.ip}, response is {str(e)}")

            if scanner.state in globals.STATE.DISCOVERED:
                logger.info(f"[WSD:state_mon] Fresh discovered, now probing...")
                try:
                    asyncio.create_task(send_probe(uuid))
                except Exception as e:
                    scanner.state = globals.STATE.ERROR
                    logger.warning(f"Anything went wrong while probing {scanner.friendly_name} @ {scanner.ip}, response is {str(e)}")

            # Timeout überschritten → offline markieren, damit werden alle Zwischenstati erschlagen, für den Fall dass was hängen geblieben ist und auch für ERROR
            if (age > OFFLINE_TIMEOUT or (subscr_age > scanner.subscription_timeout) and scanner.state not in {globals.STATE.ABSENT, globals.STATE.TO_REMOVE}):
                logger.warning(f"[WSD:Heartbeat] --> mark as offline")
                scanner.mark_absent()

            # Nach Ablauf von Timeout+Offline → entfernen
            if status == "absent" and scanner.remove_after is not None and now >= scanner.remove_after and scanner.pinned is False:
                logger.info(f"[WSD:Heartbeat] --> Marking {scanner.friendly_name} @ {scanner.ip} to remove")
                logger.info(f"[WSD:Heartbeat] Status={status}, RemoveAfter={scanner.remove_after}, now={now}, Pinned={scanner.pinned}")
                to_remove.append(scanner)

            logger.info(f"    =====> state: {globals.SCANNERS[uuid].state.value}")
    
        # welche Scanner sollen entfernt werden?
        logger.debug(f"[WSD:Heartbeat] checking for Scanners to remove from known list")
        for s in to_remove:
            logger.warning(f"[Heartbeat]     ---> Removing {scanner.friendly_name} @ {scanner.ip} from list")
            del globals.SCANNERS[scanner.uuid]
            list_scanners()

        # Entferne die abgelaufenen Jobs
        if globals.SCAN_JOBS:   # Nur wenn überhaupt Jobs existieren
            logger.debug(f"     ---> checking for Scan Jobs to remove")
            expired_jobs = []
            for job_id, job in list(globals.SCAN_JOBS.items()):
                remove_after = getattr(job, "remove_after", None)
                logger.debug(f"     ---> Job {job_id} expires on {remove_after}")
                if now >= remove_after:
                    logger.info(f"     ---> Removing expired job {job_id} (expired at {remove_after})")
                    expired_jobs.append(job_id)
            for job_id in expired_jobs:
                del globals.SCAN_JOBS[job_id]

        active_states = {
            globals.STATE.ONLINE,
            globals.STATE.ABSENT,
            globals.STATE.TO_REMOVE,
#            STATE.ERROR,
            globals.STATE.PINNED
        }
        if any(scanner.state not in active_states
               for scanner in globals.SCANNERS.values()):                                        # Es läuft gerade etwas → schnell pollen
            logger.debug(f"{datetime.datetime.now():%Y-%m-%d %H:%M:%S} [WSD:sleep] short nap because something is happening")
            await asyncio.sleep(1)
        elif any(scanner.state == globals.STATE.PINNED
                 for scanner in globals.SCANNERS.values()):                                      # Nur angepinnte Scanner überwachen
            logger.debug(f"{datetime.datetime.now():%Y-%m-%d %H:%M:%S} [WSD:sleep] waiting for pinned Scanners")
            await asyncio.sleep(20)
        else:                                                                            # Keine aktiven Scanner
            logger.debug(f"{datetime.datetime.now():%Y-%m-%d %H:%M:%S} [WSD:sleep] goodbye")
            await asyncio.sleep(OFFLINE_TIMEOUT / 7)


        # bei allen Zuständen außer [...] die kurze Pause
#        if any (scanner.state not in {STATE.ONLINE,
#                                      STATE.ABSENT,
##                                      STATE.SCAN_PENDING,
##                                      STATE.SCAN_REQ_TICKET,
##                                      STATE.SCAN_RETRIEVING,
##                                      STATE.SCAN_DONE,
##                                      STATE.SCAN_FAILED,
#                                      STATE.TO_REMOVE,
#                                      STATE.ERROR}
#                for scanner in SCANNERS.values()):
#            logger.debug(f"{datetime.datetime.now():%Y-%m-%d %H:%M:%S} [WSD:sleep] short nap")
#            await asyncio.sleep(1)
#        # sonst die lange Pause
#        else:
#            logger.debug(f"{datetime.datetime.now():%Y-%m-%d %H:%M:%S} [WSD:sleep] goodbye")
#            await asyncio.sleep(OFFLINE_TIMEOUT / 7) # damit wir iwie auf nen krummen Wert kommen

        logger.debug(f"{datetime.datetime.now():%Y-%m-%d %H:%M:%S} [WSD:sleep] back in town")


