import asyncio
from webserver import start_http_server
from wsd import discovery_listener, heartbeat_monitor
from config import WSD_HTTP_PORT, WSD_OFFLINE_TIMEOUT, WSD_SCAN_FOLDER
from scanner import Scanner, SCANNERS
#import webserver
#import wsd
#import config
#import scanner

async def main():
    await asyncio.gather(
        start_http_server(),
        discovery_listener(),
        heartbeat_monitor(),
    )

if __name__ == "__main__":
    asyncio.run(main())
