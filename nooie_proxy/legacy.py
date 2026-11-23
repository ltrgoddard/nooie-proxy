"""stream a legacy (non-webrtc) nooie camera over apeman p2p + enet.

older models (e.g. IPC100/IPC100B/IPC200A) do not answer webrtc offers and
instead serve raw hevc/h264 + g.711 a-law frames over enet after an apeman
P2pInit -> P2pInfo -> P2pConn handshake.
"""

from __future__ import annotations

import asyncio
import fractions
import hashlib
import signal
import struct
import time
from contextlib import suppress
from typing import Any

import av

from . import apeman, cloud, enet
from .apeman import Registration, block_decrypt_cbc, block_encrypt
from .cloud import Config
from .env import log
from .stream import MUX, MUXER, aligned
from .twofish import Twofish

CMD_MAGIC = bytes.fromhex("89abcdef113c2b1a")
CMD_HEARTBEAT = 0x000E
CMD_START_LIVE_AV = 0x003E
CMD_STOP_LIVE_VIDEO = 0x0011
CMD_STOP_LIVE_AUDIO = 0x0013

MEDIA_MAGIC = b"\xaa\x55"
MEDIA_AUDIO = 2
MEDIA_VIDEO = 5

HEARTBEAT_INTERVAL = 10.0
RECV_TIMEOUT = 10.0
VIDEO_BASE = fractions.Fraction(1, 90000)
VIDEO_TICK = 90000 // 30
AUDIO_RATE = 16000


def command_key(secret: str) -> bytes:
    """derive the 32-byte ascii hex md5 key used for p2p commands and media."""
    return hashlib.md5(secret.encode()).hexdigest().encode()


def build_command(
    cmd_id: int,
    payload: bytes,
    trans_id: int,
    key: bytes,
    channel: int = 0,
) -> bytes:
    """pack one 20-byte ASDP2p command header plus twofish-ecb payload."""
    body = block_encrypt(payload, key) if payload else b""
    hdr = (
        struct.pack(
            ">I8sBB", 20 + len(body), CMD_MAGIC, 0x50 | (channel & 0x0F), 0
        )
        + struct.pack("<H", cmd_id)
        + struct.pack(">I", trans_id)
    )
    return hdr + body


def decrypt_video_frame(tf: Twofish, frame: bytes) -> bytes:
    """decrypt up to 256 bytes starting at offset 16 (twofish-cbc, zero iv)."""
    if len(frame) <= 16:
        return frame
    enc_len = 256 if len(frame) >= 272 else ((len(frame) - 16) & ~0xF)
    if enc_len == 0:
        return frame
    mid = block_decrypt_cbc(frame[16 : 16 + enc_len], tf)
    return frame[:16] + mid + frame[16 + enc_len :]


def detect_video_codec(frame: bytes) -> str | None:
    """identify an annex-b keyframe as hevc (vps 0x40) or h264 (sps 0x67)."""
    if len(frame) < 5 or frame[:4] != b"\x00\x00\x00\x01":
        return None
    nal = frame[4]
    if nal == 0x40:
        return "hevc"
    if (nal & 0x1F) == 7:
        return "h264"
    return None


def parse_media_fragment(
    raw: bytes,
) -> tuple[int, int, int, int, bytes] | None:
    """parse a 16-byte 0xaa55 media packet -> (kind, flags, seq, ts, data)."""
    if len(raw) < 16 or raw[4:6] != MEDIA_MAGIC:
        return None
    kind, flags, seq, plen, ts = struct.unpack(">BBHHI", raw[6:16])
    return kind, flags, seq, ts, raw[16 : 16 + plen]


class LegacyMux:
    """mux decrypted annex-b video + g.711 a-law audio into mpeg-ts."""

    def __init__(self, target: str, video_codec: str) -> None:
        self.container = av.open(
            aligned(target), "w", format=MUXER, options=MUX
        )
        self.video = self.container.add_mux_stream(
            video_codec, time_base=VIDEO_BASE
        )
        self.audio = self.container.add_stream(
            "aac", rate=AUDIO_RATE, layout="mono"
        )
        self.audio.bit_rate = 32000
        self._alaw: Any = av.CodecContext.create("pcm_alaw", "r")
        self._alaw.sample_rate = 8000
        self._alaw.layout = "mono"
        self._resampler = av.AudioResampler(
            format="fltp", layout="mono", rate=AUDIO_RATE
        )
        self._origin = time.monotonic()
        self._last_vpts = -VIDEO_TICK
        self._audio_samples = 0

    def write_video(self, frame: bytes) -> None:
        now = round((time.monotonic() - self._origin) / VIDEO_BASE)
        stamp = max(self._last_vpts + VIDEO_TICK, now)
        self._last_vpts = stamp
        pkt = av.Packet(frame)
        pkt.stream = self.video
        pkt.time_base = VIDEO_BASE
        pkt.pts = pkt.dts = stamp
        self.container.mux(pkt)

    def write_audio(self, alaw: bytes) -> None:
        for decoded in self._alaw.decode(av.Packet(alaw)):
            for resampled in self._resampler.resample(decoded):
                resampled.pts = self._audio_samples
                self._audio_samples += resampled.samples
                for pkt in self.audio.encode(resampled):
                    self.container.mux(pkt)

    def close(self) -> None:
        with suppress(Exception):
            for pkt in self.audio.encode(None):
                self.container.mux(pkt)
        self.container.close()


async def stream(
    config: Config, registration: Registration, target: str
) -> None:
    """stream a legacy camera over apeman p2p + enet until stopped."""
    if not config.hb_domain or not config.hb_port or not config.secret:
        raise RuntimeError(
            "camera record is missing legacy p2p fields (hb_domain/secret)"
        )
    token, schema = cloud.p2p_claims(config.api_token)
    log(f"punching legacy p2p via {config.hb_domain}:{config.hb_port}")
    punch = await asyncio.to_thread(
        apeman.punch,
        config.uid,
        token,
        schema,
        registration,
        config.device_id,
        config.hb_domain,
        config.hb_port,
    )

    client = enet.Client(
        punch.lan_ip, punch.local_port, punch.peer_ip, punch.peer_port
    )
    stopping = asyncio.Event()
    stop_why = ""

    def request_stop(reason: str) -> None:
        nonlocal stop_why
        stop_why = stop_why or reason
        stopping.set()

    loop = asyncio.get_running_loop()
    for number in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(number, request_stop, "this process was stopped")

    key = command_key(config.secret)
    tf = Twofish(key)
    mux: LegacyMux | None = None
    cmd_tid = 1
    streaming = 0.0

    try:
        await client.connect()
        log(f"legacy p2p connected to {punch.peer_ip}:{punch.peer_port}")
        client.send_reliable(
            1,
            build_command(
                CMD_START_LIVE_AV, struct.pack("<IIII", 0, 0, 0, 0), cmd_tid, key
            ),
        )
        cmd_tid += 1

        vid_buf = bytearray()
        last_hb = time.monotonic()
        while not stopping.is_set():
            now = time.monotonic()
            if now - last_hb >= HEARTBEAT_INTERVAL:
                client.send_reliable(
                    1,
                    build_command(CMD_HEARTBEAT, bytes(104), cmd_tid, key),
                )
                cmd_tid += 1
                last_hb = now
            try:
                _ch, raw = await client.recv(timeout=RECV_TIMEOUT)
            except TimeoutError:
                request_stop("the camera stopped sending packets")
                break
            except RuntimeError as error:
                request_stop(str(error))
                break

            frag = parse_media_fragment(raw)
            if frag is None:
                continue
            kind, flags, _seq, _ts, payload = frag
            if kind == MEDIA_VIDEO:
                vid_buf.extend(payload)
                if flags & 0x01:
                    frame = decrypt_video_frame(tf, bytes(vid_buf))
                    vid_buf.clear()
                    if mux is None:
                        codec = detect_video_codec(frame)
                        if codec is None:
                            continue
                        mux = LegacyMux(target, codec)
                        streaming = time.monotonic()
                        log(f"streaming {codec} over legacy p2p to {target}")
                    try:
                        mux.write_video(frame)
                    except Exception as error:  # noqa: BLE001
                        request_stop(f"the video sink failed: {error}")
                        break
            elif kind == MEDIA_AUDIO and mux is not None:
                alaw = block_decrypt_cbc(payload, tf)
                try:
                    mux.write_audio(alaw)
                except Exception as error:  # noqa: BLE001
                    request_stop(f"the audio sink failed: {error}")
                    break
    finally:
        with suppress(Exception):
            client.send_reliable(
                1, build_command(CMD_STOP_LIVE_VIDEO, b"", cmd_tid, key)
            )
            client.send_reliable(
                1, build_command(CMD_STOP_LIVE_AUDIO, b"", cmd_tid + 1, key)
            )
        client.disconnect()
        if mux is not None:
            with suppress(OSError):
                mux.close()
        if streaming:
            log(
                f"call ended after {time.monotonic() - streaming:.0f} s of "
                f"streaming: {stop_why or 'an unknown cause'}"
            )
