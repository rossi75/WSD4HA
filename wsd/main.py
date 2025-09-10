import asyncio
from webserver import start_http_server
from wsd import discovery_listener, heartbeat_monitor

async def main():
    await asyncio.gather(
        start_http_server(),
        discovery_listener(),
        heartbeat_monitor(),
    )

if __name__ == "__main__":
    asyncio.run(main())
