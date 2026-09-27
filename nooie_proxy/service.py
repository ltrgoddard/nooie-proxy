"""nooie-proxy: sign in to a nooie camera and put its stream on stdout."""

import asyncio
import sys

import aiohttp

from . import apeman, cloud
from .env import load_environment, log, output
from .stream import stream


async def serve() -> None:
    target = output()
    async with aiohttp.ClientSession(
        timeout=aiohttp.ClientTimeout(total=30)
    ) as http:
        config = await cloud.login(http)
        # publish our nat mapping on nooie's p2p network so the camera can
        # reach us; the registration holds its udp socket open.
        registration = await asyncio.to_thread(
            apeman.register, config.uid, config.p2p
        )
        # enough of the mapping to tell a nat problem apart from a working
        # one, without putting the user's public address in a log they may
        # well paste into an issue.
        masked = registration.wan_ip.rsplit(".", 1)[0] + ".x"
        log(f"p2p registered from {masked}")
        await stream(config, target)


async def list_devices() -> None:
    """print every camera on the account so NOOIE_DEVICE_ID can be chosen."""
    async with aiohttp.ClientSession(
        timeout=aiohttp.ClientTimeout(total=30)
    ) as http:
        _, devices = await cloud.signed_in(http)
    print("uuid\tname\tmodel\tonline")
    for device in devices:
        print(
            "\t".join(
                (
                    str(device.get("uuid", "")),
                    str(device.get("name", "")),
                    str(device.get("type", "")),
                    "yes" if int(device.get("online", 0)) == 1 else "no",
                )
            )
        )


# what the app's inbox calls each alert. the rest print as their number.
KINDS = {8: "motion", 9: "sound", 13: "cry"}
# how often to ask. an alert reaches the list only after the camera has
# uploaded its snapshot, so asking faster than this buys little.
POLL = 5


async def events() -> None:
    """print each new alert as it arrives: uuid, kind, and when, in unix time.

    only alerts newer than the first look are printed, so a restart does not
    replay the inbox.
    """
    seen: dict[str, int] = {}
    async with aiohttp.ClientSession(
        timeout=aiohttp.ClientTimeout(total=30)
    ) as http:
        config, devices = await cloud.signed_in(http)
        while True:
            for device in (str(d.get("uuid", "")) for d in devices):
                try:
                    found = await cloud.events(http, config, device)
                except RuntimeError:
                    # the session was refused: take the shared one, or sign in.
                    config, devices = await cloud.signed_in(http)
                    break
                except (aiohttp.ClientError, TimeoutError) as error:
                    log(f"could not read events: {error}")
                    continue
                last = seen.get(device)
                for event in sorted(found, key=lambda e: int(e["id"])):
                    if last is not None and int(event["id"]) > last:
                        kind = KINDS.get(event["type"], str(event["type"]))
                        print(f"{device}\t{kind}\t{event['time']}", flush=True)
                seen[device] = max([last or 0, *(int(e["id"]) for e in found)])
            await asyncio.sleep(POLL)


def main(argv: list[str] | None = None) -> None:
    argv = sys.argv[1:] if argv is None else argv
    load_environment()
    try:
        if "--list-devices" in argv:
            asyncio.run(list_devices())
        elif "--events" in argv:
            asyncio.run(events())
        else:
            asyncio.run(serve())
    except (RuntimeError, OSError, aiohttp.ClientError) as error:
        # whatever reads this keeps the last line, and the last line of a
        # traceback is the least useful part of it. these are the failures
        # the account and the network raise: say them and stop.
        raise SystemExit(str(error)) from None
