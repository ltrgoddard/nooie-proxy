"""minimal pure-python enet 1.3 client for legacy nooie p2p streams.

older nooie cameras run libenet over the hole-punched udp socket rather than
webrtc. implementing the client side directly in python keeps nooie-proxy
dependency-free (including on alpine/musl containers like home assistant os).
"""

from __future__ import annotations

import asyncio
import random
import socket
import struct
import time
from collections import deque
from dataclasses import dataclass, field

# enet protocol flags and command ids (enet/protocol.h).
_HEADER_FLAG_SENT_TIME = 0x8000
_HEADER_SESSION_SHIFT = 12
_HEADER_PEER_MASK = 0x0FFF
_MAX_PEER_ID = 0x0FFF

_FLAG_ACKNOWLEDGE = 0x80
_CMD_MASK = 0x0F

CMD_ACKNOWLEDGE = 1
CMD_CONNECT = 2
CMD_VERIFY_CONNECT = 3
CMD_DISCONNECT = 4
CMD_PING = 5
CMD_SEND_RELIABLE = 6
CMD_SEND_UNRELIABLE = 7
CMD_SEND_FRAGMENT = 8
CMD_SEND_UNSEQUENCED = 9
CMD_BANDWIDTH_LIMIT = 10
CMD_THROTTLE_CONFIGURE = 11
CMD_SEND_UNRELIABLE_FRAGMENT = 12

_DEFAULT_MTU = 1400
_DEFAULT_WINDOW = 32768
_MAX_RELIABLE_PAYLOAD = 1300
_PING_INTERVAL = 0.5
_RESEND_INTERVAL = 0.25


def _now_ms16() -> int:
    return int(time.monotonic() * 1000) & 0xFFFF


def _seq_next(seq: int) -> int:
    return (seq + 1) & 0xFFFF


def _seq_less(a: int, b: int) -> bool:
    return ((a - b) & 0xFFFF) > 0x8000


@dataclass
class _FragmentBuf:
    count: int
    total: int
    buf: bytearray
    received: set[int] = field(default_factory=set)


@dataclass
class _Pending:
    channel: int
    seq: int
    cmd_bytes: bytes
    sent_at: float
    retries: int = 0


class Client:
    """single-peer enet 1.3 client bound to a specific local udp endpoint."""

    def __init__(
        self,
        local_ip: str,
        local_port: int,
        peer_ip: str,
        peer_port: int,
        channels: int = 2,
    ) -> None:
        self.local_addr = (local_ip, local_port)
        self.peer_addr = (peer_ip, peer_port)
        self.channels = channels
        self._sock: socket.socket | None = None
        self._peer_id = _MAX_PEER_ID
        self._session_id = 0
        self._connect_id = random.randint(1, 0xFFFFFFFF)
        self._connected = False
        self._disconnected = False
        self._out_seq: dict[int, int] = {0xFF: 0}
        self._in_seq: dict[int, int] = {}
        self._reorder: dict[int, dict[int, tuple[bytes, int]]] = {}
        self._fragments: dict[tuple[int, int], _FragmentBuf] = {}
        self._pending: dict[tuple[int, int], _Pending] = {}
        self._inbox: deque[tuple[int, bytes]] = deque()
        self._last_ping = 0.0
        for ch in range(channels):
            self._out_seq[ch] = 0
            self._in_seq[ch] = 1
            self._reorder[ch] = {}

    def _open_socket(self) -> socket.socket:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(self.local_addr)
        sock.setblocking(False)
        self._sock = sock
        return sock

    def _next_out_seq(self, channel: int) -> int:
        seq = _seq_next(self._out_seq.get(channel, 0))
        self._out_seq[channel] = seq
        return seq

    def _send_raw(self, payload: bytes, *, with_time: bool = True) -> None:
        if self._sock is None:
            return
        peer_field = self._peer_id & _HEADER_PEER_MASK
        if self._peer_id != _MAX_PEER_ID:
            peer_field |= (self._session_id & 0x03) << _HEADER_SESSION_SHIFT
        if with_time:
            hdr = struct.pack(
                ">HH", peer_field | _HEADER_FLAG_SENT_TIME, _now_ms16()
            )
        else:
            hdr = struct.pack(">H", peer_field)
        self._sock.sendto(hdr + payload, self.peer_addr)

    def _send_ack(self, channel: int, seq: int, sent_time: int) -> None:
        cmd = struct.pack(
            ">BBHHH", CMD_ACKNOWLEDGE, channel, seq, seq, sent_time
        )
        self._send_raw(cmd, with_time=False)

    def _queue_reliable(self, channel: int, seq: int, cmd_bytes: bytes) -> None:
        self._pending[(channel, seq)] = _Pending(
            channel=channel,
            seq=seq,
            cmd_bytes=cmd_bytes,
            sent_at=time.monotonic(),
        )
        self._send_raw(cmd_bytes, with_time=True)

    def _resend_due(self) -> None:
        now = time.monotonic()
        for item in list(self._pending.values()):
            if now - item.sent_at >= _RESEND_INTERVAL:
                item.sent_at = now
                item.retries += 1
                self._send_raw(item.cmd_bytes, with_time=True)
        if self._connected and now - self._last_ping >= _PING_INTERVAL:
            self._last_ping = now
            seq = self._next_out_seq(0xFF)
            cmd = struct.pack(">BBH", CMD_PING | _FLAG_ACKNOWLEDGE, 0xFF, seq)
            self._queue_reliable(0xFF, seq, cmd)

    def _deliver_reliable(
        self, channel: int, seq: int, data: bytes, span: int = 1
    ) -> None:
        expected = self._in_seq.setdefault(channel, 1)
        if _seq_less(seq, expected):
            return
        if seq == expected:
            self._inbox.append((channel, data))
            expected = (expected + span) & 0xFFFF
            buf = self._reorder.setdefault(channel, {})
            while expected in buf:
                pkt, pspan = buf.pop(expected)
                self._inbox.append((channel, pkt))
                expected = (expected + pspan) & 0xFFFF
            self._in_seq[channel] = expected
        else:
            self._reorder.setdefault(channel, {})[seq] = (data, span)

    def _handle_datagram(self, raw: bytes) -> None:
        if len(raw) < 2:
            return
        peer_field = struct.unpack_from(">H", raw, 0)[0]
        pos = 2
        sent_time = 0
        if peer_field & _HEADER_FLAG_SENT_TIME:
            if len(raw) < 4:
                return
            sent_time = struct.unpack_from(">H", raw, 2)[0]
            pos = 4

        while pos + 4 <= len(raw):
            cmd_byte, channel, rseq = struct.unpack_from(">BBH", raw, pos)
            cmd = cmd_byte & _CMD_MASK
            need_ack = bool(cmd_byte & _FLAG_ACKNOWLEDGE)

            if cmd == CMD_ACKNOWLEDGE:
                if pos + 8 > len(raw):
                    break
                ack_seq = struct.unpack_from(">H", raw, pos + 4)[0]
                self._pending.pop((channel, ack_seq), None)
                pos += 8
            elif cmd == CMD_VERIFY_CONNECT:
                if pos + 44 > len(raw):
                    break
                out_peer, in_sess, _out_sess = struct.unpack_from(
                    ">HBB", raw, pos + 4
                )
                self._peer_id = out_peer & _HEADER_PEER_MASK
                self._session_id = in_sess & 0x03
                self._connected = True
                self._last_ping = time.monotonic()
                if need_ack:
                    self._send_ack(channel, rseq, sent_time)
                pos += 44
            elif cmd == CMD_DISCONNECT:
                self._disconnected = True
                if need_ack:
                    self._send_ack(channel, rseq, sent_time)
                pos += 8
            elif cmd == CMD_PING:
                if need_ack:
                    self._send_ack(channel, rseq, sent_time)
                pos += 4
            elif cmd == CMD_SEND_RELIABLE:
                if pos + 6 > len(raw):
                    break
                dlen = struct.unpack_from(">H", raw, pos + 4)[0]
                end = pos + 6 + dlen
                if end > len(raw):
                    break
                if need_ack:
                    self._send_ack(channel, rseq, sent_time)
                self._deliver_reliable(channel, rseq, raw[pos + 6 : end])
                pos = end
            elif cmd == CMD_SEND_UNRELIABLE:
                if pos + 8 > len(raw):
                    break
                dlen = struct.unpack_from(">H", raw, pos + 6)[0]
                end = pos + 8 + dlen
                if end > len(raw):
                    break
                self._inbox.append((channel, raw[pos + 8 : end]))
                pos = end
            elif cmd in (CMD_SEND_FRAGMENT, CMD_SEND_UNRELIABLE_FRAGMENT):
                if pos + 24 > len(raw):
                    break
                start_seq, dlen, fcnt, fnum, total, foff = struct.unpack_from(
                    ">HHIIII", raw, pos + 4
                )
                end = pos + 24 + dlen
                if end > len(raw):
                    break
                if need_ack:
                    self._send_ack(channel, rseq, sent_time)
                key = (channel, start_seq)
                fbuf = self._fragments.get(key)
                if fbuf is None and 0 < fcnt <= 256 and total <= (1 << 20):
                    fbuf = _FragmentBuf(fcnt, total, bytearray(total))
                    self._fragments[key] = fbuf
                if fbuf is not None and foff + dlen <= fbuf.total:
                    fbuf.buf[foff : foff + dlen] = raw[pos + 24 : end]
                    fbuf.received.add(fnum)
                    if len(fbuf.received) >= fbuf.count:
                        del self._fragments[key]
                        if cmd == CMD_SEND_FRAGMENT:
                            self._deliver_reliable(
                                channel,
                                start_seq,
                                bytes(fbuf.buf),
                                span=fbuf.count,
                            )
                        else:
                            self._inbox.append((channel, bytes(fbuf.buf)))
                pos = end
            elif cmd == CMD_SEND_UNSEQUENCED:
                if pos + 8 > len(raw):
                    break
                dlen = struct.unpack_from(">H", raw, pos + 6)[0]
                end = pos + 8 + dlen
                if end > len(raw):
                    break
                self._inbox.append((channel, raw[pos + 8 : end]))
                pos = end
            elif cmd == CMD_BANDWIDTH_LIMIT:
                pos += 12
            elif cmd == CMD_THROTTLE_CONFIGURE:
                pos += 16
            elif cmd == CMD_CONNECT:
                pos += 48
            else:
                break

    async def connect(self, timeout: float = 5.0) -> None:
        """perform the enet CONNECT / VERIFY_CONNECT handshake."""
        sock = self._open_socket()
        loop = asyncio.get_running_loop()
        seq = self._next_out_seq(0xFF)
        cmd = struct.pack(
            ">BBHHBBIIIIIIIIII",
            CMD_CONNECT | _FLAG_ACKNOWLEDGE,
            0xFF,
            seq,
            0,  # outgoingPeerID (client slot 0)
            0,  # incomingSessionID
            0,  # outgoingSessionID
            _DEFAULT_MTU,
            _DEFAULT_WINDOW,
            self.channels,
            0,  # incomingBandwidth
            0,  # outgoingBandwidth
            5000,  # packetThrottleInterval
            2,  # packetThrottleAcceleration
            2,  # packetThrottleDeceleration
            self._connect_id,
            0,  # data
        )
        self._queue_reliable(0xFF, seq, cmd)
        deadline = time.monotonic() + timeout
        while not self._connected and not self._disconnected:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                self.close()
                raise RuntimeError("ENet connection to camera timed out")
            try:
                async with asyncio.timeout(min(0.25, remaining)):
                    data = await loop.sock_recv(sock, 4096)
                self._handle_datagram(data)
            except TimeoutError:
                self._resend_due()
        if self._disconnected:
            self.close()
            raise RuntimeError("camera disconnected during ENet handshake")

    def send_reliable(self, channel: int, data: bytes) -> None:
        """queue a reliable packet on `channel`."""
        if len(data) > _MAX_RELIABLE_PAYLOAD:
            raise ValueError("packet exceeds ENet MTU")
        seq = self._next_out_seq(channel)
        cmd = (
            struct.pack(
                ">BBHH",
                CMD_SEND_RELIABLE | _FLAG_ACKNOWLEDGE,
                channel,
                seq,
                len(data),
            )
            + data
        )
        self._queue_reliable(channel, seq, cmd)

    async def recv(self, timeout: float = 10.0) -> tuple[int, bytes]:
        """return the next `(channel, payload)` from the camera."""
        if self._inbox:
            return self._inbox.popleft()
        if self._sock is None:
            raise RuntimeError("ENet socket is closed")
        loop = asyncio.get_running_loop()
        deadline = time.monotonic() + timeout
        while not self._inbox:
            if self._disconnected:
                raise RuntimeError("camera disconnected ENet peer")
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("no ENet packets received before timeout")
            try:
                async with asyncio.timeout(min(0.25, remaining)):
                    data = await loop.sock_recv(self._sock, 65536)
                self._handle_datagram(data)
                self._resend_due()
            except TimeoutError:
                self._resend_due()
        return self._inbox.popleft()

    def disconnect(self) -> None:
        """send a best-effort ENet DISCONNECT and close the socket."""
        if self._sock is not None and self._connected:
            cmd = struct.pack(">BBHI", CMD_DISCONNECT, 0xFF, 0, 0)
            try:
                self._send_raw(cmd, with_time=False)
            except OSError:
                pass
        self.close()

    def close(self) -> None:
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None
        self._connected = False
