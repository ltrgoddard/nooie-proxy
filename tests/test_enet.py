import struct
import unittest

from nooie_proxy import enet


class FakeSocket:
    def __init__(self) -> None:
        self.sent: list[tuple[bytes, tuple[str, int]]] = []

    def sendto(self, data: bytes, addr: tuple[str, int]) -> int:
        self.sent.append((data, addr))
        return len(data)

    def close(self) -> None:
        pass


class ENetClientTests(unittest.TestCase):
    def _client(self) -> tuple[enet.Client, FakeSocket]:
        client = enet.Client("127.0.0.1", 40000, "127.0.0.1", 40001)
        sock = FakeSocket()
        client._sock = sock  # type: ignore[assignment]
        return client, sock

    def test_verify_connect_sets_peer_and_acks(self) -> None:
        client, sock = self._client()
        verify = struct.pack(
            ">HHBBHHBBIIIIIIIII",
            0x8000 | 0,  # header peer_id + sent_time flag
            1234,  # sent_time
            enet.CMD_VERIFY_CONNECT | 0x80,
            0xFF,
            1,  # reliable seq
            42,  # server outgoingPeerID
            2,  # incomingSessionID
            1,  # outgoingSessionID
            1400,
            32768,
            2,
            0,
            0,
            5000,
            2,
            2,
            client._connect_id,
        )
        client._handle_datagram(verify)
        self.assertTrue(client._connected)
        self.assertEqual(client._peer_id, 42)
        self.assertEqual(client._session_id, 2)
        self.assertEqual(len(sock.sent), 1)
        ack_pkt, _ = sock.sent[0]
        peer_field = struct.unpack_from(">H", ack_pkt, 0)[0]
        self.assertEqual(peer_field, 42 | (2 << 12))
        cmd, ch, seq, ack_seq, ack_time = struct.unpack_from(
            ">BBHHH", ack_pkt, 2
        )
        self.assertEqual((cmd, ch, seq, ack_seq, ack_time), (1, 0xFF, 1, 1, 1234))

    def test_reliable_reordering_and_dedup(self) -> None:
        client, _ = self._client()
        client._connected = True

        def make_rel(seq: int, payload: bytes) -> bytes:
            return (
                struct.pack(
                    ">HHBBHH",
                    0x8000,
                    10,
                    enet.CMD_SEND_RELIABLE | 0x80,
                    1,
                    seq,
                    len(payload),
                )
                + payload
            )

        # seq 2 arrives before seq 1
        client._handle_datagram(make_rel(2, b"second"))
        self.assertEqual(len(client._inbox), 0)
        client._handle_datagram(make_rel(1, b"first"))
        self.assertEqual(list(client._inbox), [(1, b"first"), (1, b"second")])
        # duplicate seq 1 is ignored
        client._inbox.clear()
        client._handle_datagram(make_rel(1, b"first"))
        self.assertEqual(len(client._inbox), 0)

    def test_fragment_reassembly_advances_sequence(self) -> None:
        client, _ = self._client()
        client._connected = True

        def make_frag(seq: int, fnum: int, foff: int, data: bytes) -> bytes:
            return (
                struct.pack(
                    ">HHBBHHHIIII",
                    0x8000,
                    20,
                    enet.CMD_SEND_FRAGMENT | 0x80,
                    1,
                    seq,
                    1,  # start_seq
                    len(data),
                    2,  # fragment_count
                    fnum,
                    10,  # total_length
                    foff,
                )
                + data
            )

        client._handle_datagram(make_frag(1, 0, 0, b"hello"))
        self.assertEqual(len(client._inbox), 0)
        client._handle_datagram(make_frag(2, 1, 5, b"world"))
        self.assertEqual(list(client._inbox), [(1, b"helloworld")])
        # next expected seq on channel 1 must be 3 (1 + 2 fragments)
        self.assertEqual(client._in_seq[1], 3)


if __name__ == "__main__":
    unittest.main()
