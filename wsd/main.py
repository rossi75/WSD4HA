import asyncio
from server import start_http_server, start_notify_server
from wsd import UDP_listener_3702, state_monitor
#from config import HTTP_PORT, OFFLINE_TIMEOUT, SCAN_FOLDER
#from scanner import Scanner

async def main():
    await asyncio.gather(
        start_http_server(),
        start_notify_server(),
        UDP_listener_3702(),
        state_monitor(),
    )

if __name__ == "__main__":
    asyncio.run(main())
