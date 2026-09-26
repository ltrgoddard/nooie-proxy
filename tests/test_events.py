import asyncio
import contextlib
import io
import unittest
from unittest.mock import AsyncMock, patch

from nooie_proxy import service


class Events(unittest.TestCase):
    def test_only_alerts_after_the_first_look_are_printed(self) -> None:
        old = {"id": 1, "type": 8, "time": 100}
        looks = [[old], [{"id": 3, "type": 13, "time": 300}, old]]
        sleeps = AsyncMock(side_effect=[None, asyncio.CancelledError])
        out = io.StringIO()
        with (
            patch.object(
                service.cloud,
                "signed_in",
                AsyncMock(return_value=(None, [{"uuid": "cam"}])),
            ),
            patch.object(
                service.cloud, "events", AsyncMock(side_effect=looks)
            ),
            patch.object(service.asyncio, "sleep", sleeps),
            contextlib.redirect_stdout(out),
            self.assertRaises(asyncio.CancelledError),
        ):
            asyncio.run(service.events())
        self.assertEqual(out.getvalue(), "cam\tcry\t300\n")


if __name__ == "__main__":
    unittest.main()
