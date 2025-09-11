import asyncio
from webserver import start_http_server
#import webserver
#from wsd import UDP_listener_3702, heartbeat_monitor, handle_scan_job
from wsd import UDP_listener_3702, heartbeat_monitor
#import wsd
from config import WSD_HTTP_PORT, WSD_OFFLINE_TIMEOUT, WSD_SCAN_FOLDER
#import config
#from scanner import Scanner, SCANNERS
from scanner import Scanner
#import scanner
#from state import SCANNERS
#from globals import SCANNERS

async def main():
    await asyncio.gather(
 #       start_http_server(),
        UDP_listener_3702(),
#        discovery_listener(),
        heartbeat_monitor(),
    )

if __name__ == "__main__":
    asyncio.run(main())
