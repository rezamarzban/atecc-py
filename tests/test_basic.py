import io
import os
import sys
import unittest
from contextlib import redirect_stdout

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from atecc import Chip, config_zone as cz
from atecc.chips import detect
from atecc.cli import main
from atecc.crc import crc16, crc16_le
from atecc.protocol import frame
from atecc.transports.sim import SimTransport, default_config


class CrcAndFraming(unittest.TestCase):
    def test_wake_response_crc(self):
        # the fixed wake reply is 04 11 33 43
        self.assertEqual(crc16_le(bytes([0x04, 0x11])), bytes([0x33, 0x43]))

    def test_info_frame(self):
        # known-good DevRev request: 03 07 30 00 00 00 03 5D
        self.assertEqual(frame(0x30, 0, 0).hex(), "03073000000003" + "5d")


class Protocol(unittest.TestCase):
    def setUp(self):
        self.sim = SimTransport()
        self.chip = Chip(self.sim, retries=2)

    def test_detect_and_serial(self):
        self.assertEqual(self.chip.profile.name, "ATECC608A")
        self.assertEqual(self.chip.serial().hex(), "0123aabb" + "11223344ee")

    def test_read_config_matches(self):
        self.assertEqual(self.chip.read_config(), bytes(self.sim.config))

    def test_sha204_config_88_bytes(self):
        sim = SimTransport(config=default_config(rev=bytes([0, 2, 0, 9]), size=88))
        chip = Chip(sim)
        self.assertEqual(chip.profile.name, "ATSHA204A")
        self.assertEqual(chip.read_config(), bytes(sim.config))

    def test_counter(self):
        self.sim.counters[0] = 5
        self.assertEqual(self.chip.counter_read(0), 5)

    def test_lock_flags(self):
        cfg = self.chip.read_config()
        self.assertFalse(cz.is_config_locked(cfg))
        self.assertFalse(cz.is_data_locked(cfg))
        self.assertFalse(cz.is_slot_locked(cfg, 3))

    def test_detect_table(self):
        self.assertEqual(detect(bytes([0, 0, 0x60, 3])).name, "ATECC608B")
        self.assertEqual(detect(bytes([0, 0, 0x50, 0])).name, "ATECC508A")


class Cli(unittest.TestCase):
    def run_cli(self, *args):
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = main(["-t", "sim"] + list(args))
        return rc, buf.getvalue()

    def test_serial_info(self):
        rc, out = self.run_cli("-c", "serial", "-c", "info")
        self.assertEqual(rc, 0)
        self.assertIn("0123aabb11223344ee", out)
        self.assertIn("Found ATECC608A", out)

    def test_dump_config(self):
        rc, out = self.run_cli("-c", "dump-config -")
        self.assertEqual(rc, 0)
        self.assertIn("Slot 00: unlocked", out)
        self.assertIn("KeyType: 4 [P256]", out)

    def test_lock_exit_codes(self):
        self.assertEqual(self.run_cli("-c", "config-is-locked")[0], 1)

    def test_unknown_command(self):
        self.assertEqual(self.run_cli("-c", "bogus")[0], 1)


if __name__ == "__main__":
    unittest.main()
