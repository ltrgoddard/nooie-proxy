import base64
import json
import struct
import unittest

from nooie_proxy import apeman, cloud, legacy, service
from nooie_proxy.twofish import Twofish


def _cbc_encrypt(tf: Twofish, data: bytes) -> bytes:
    out = bytearray()
    prev = bytes(16)
    for i in range(0, len(data), 16):
        blk = bytes(a ^ b for a, b in zip(data[i : i + 16], prev))
        ct = tf.encrypt(blk)
        out.extend(ct)
        prev = ct
    return bytes(out)


class LegacyP2PTests(unittest.TestCase):
    def test_p2p_claims_from_jwt(self) -> None:
        payload = base64.urlsafe_b64encode(
            json.dumps({"t_id": "a" * 32, "sch": "b" * 16}).encode()
        ).rstrip(b"=")
        token = f"hdr.{payload.decode()}.sig"
        self.assertEqual(cloud.p2p_claims(token), ("a" * 32, "b" * 16))

    def test_twofish_cbc_roundtrip_with_tail(self) -> None:
        tf = Twofish(legacy.command_key("test-secret-1234"))
        plain = bytes(range(37))
        ct = _cbc_encrypt(tf, plain[:32]) + plain[32:]
        self.assertEqual(apeman.block_decrypt_cbc(ct, tf), plain)

    def test_decrypt_video_frame_layout(self) -> None:
        tf = Twofish(legacy.command_key("test-secret-1234"))
        head = b"\x00\x00\x00\x01\x40\x01" + b"\x11" * 10
        mid = bytes(range(256))
        tail = b"cleartext-tail-bytes"
        encrypted = head + _cbc_encrypt(tf, mid) + tail
        self.assertEqual(
            legacy.decrypt_video_frame(tf, encrypted), head + mid + tail
        )

    def test_detect_video_codec(self) -> None:
        self.assertEqual(
            legacy.detect_video_codec(b"\x00\x00\x00\x01\x40\x01"), "hevc"
        )
        self.assertEqual(
            legacy.detect_video_codec(b"\x00\x00\x00\x01\x67\x42"), "h264"
        )
        self.assertIsNone(
            legacy.detect_video_codec(b"\x00\x00\x00\x01\x02\x01")
        )

    def test_build_command_header(self) -> None:
        key = legacy.command_key("secret")
        pkt = legacy.build_command(
            legacy.CMD_START_LIVE_AV, struct.pack("<IIII", 0, 0, 0, 0), 7, key
        )
        total, magic, flags, zero = struct.unpack_from(">I8sBB", pkt, 0)
        cmd_id = struct.unpack_from("<H", pkt, 14)[0]
        tid = struct.unpack_from(">I", pkt, 16)[0]
        self.assertEqual(total, len(pkt))
        self.assertEqual(magic, legacy.CMD_MAGIC)
        self.assertEqual((flags, zero, cmd_id, tid), (0x50, 0, 0x003E, 7))
        dec = apeman.block_decrypt(pkt[20:], key)
        self.assertEqual(dec, bytes(16))

    def test_parse_media_fragment(self) -> None:
        payload = b"\xde\xad\xbe\xef"
        raw = (
            struct.pack(">I2sBBHHI", 20, b"\xaa\x55", 5, 0x81, 3, 4, 999)
            + payload
        )
        self.assertEqual(
            legacy.parse_media_fragment(raw), (5, 0x81, 3, 999, payload)
        )
        self.assertIsNone(legacy.parse_media_fragment(b"short"))

    def test_should_fallback(self) -> None:
        self.assertTrue(
            service._should_fallback("no usable answer within 30 seconds")
        )
        self.assertTrue(
            service._should_fallback("session request failed: code=1104")
        )
        self.assertFalse(
            service._should_fallback("Nooie signalling refused: HTTP 401")
        )


if __name__ == "__main__":
    unittest.main()
