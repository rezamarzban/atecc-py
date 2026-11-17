"""End-to-end command tests against the simulator (full flows through the CLI)."""
import hashlib
import hmac
import io
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from atecc import Chip
from atecc.cli import main
from atecc.transports import sim as simmod
from atecc.transports.sim import SimTransport, default_config

try:
    import cryptography  # noqa: F401
    HAVE_CRYPTO = True
except ImportError:
    HAVE_CRYPTO = False


class Base(unittest.TestCase):
    def setUp(self):
        self.sim = SimTransport(busy_polls=0)
        simmod.SHARED = self.sim
        self.tmp = tempfile.mkdtemp()

    def tearDown(self):
        simmod.SHARED = None

    def p(self, name):
        return os.path.join(self.tmp, name)

    def put(self, name, data):
        with open(self.p(name), "wb") as f:
            f.write(data)
        return self.p(name)

    def get(self, name):
        with open(self.p(name), "rb") as f:
            return f.read()

    def run_cli(self, *cmds, extra=()):
        args = ["-t", "sim", "-r", "1"] + list(extra)
        for c in cmds:
            args += ["-c", c]
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            rc = main(args)
        return rc, out.getvalue(), err.getvalue()

    def lock_config(self):
        self.assertEqual(self.run_cli("lock-config", extra=["--yes-lock"])[0], 0)


class ConfigAndLocks(Base):
    def test_lock_requires_confirmation(self):
        rc, _, err = self.run_cli("lock-config")
        self.assertEqual(rc, 1)
        self.assertIn("--yes-lock", err)
        self.assertFalse(self.sim.config_locked)

    def test_write_config_roundtrip_and_lock(self):
        blob = bytearray(self.sim.config)
        blob[20:22] = bytes([0x11, 0x22])          # slot 0 SlotConfig
        blob[96:98] = bytes([0x33, 0x00])
        path = self.put("cfg.bin", bytes(blob))
        self.assertEqual(self.run_cli("write-config %s" % path)[0], 0)
        # counter config (52..67) is re-initialised by write-config, as in the C tool
        self.assertEqual(bytes(self.sim.config[16:52]), bytes(blob[16:52]))
        self.assertEqual(bytes(self.sim.config[68:84]), bytes(blob[68:84]))
        self.assertEqual(bytes(self.sim.config[88:]), bytes(blob[88:]))
        self.lock_config()
        self.assertTrue(self.sim.config_locked)
        rc, out, _ = self.run_cli("config-is-locked", "data-is-locked")
        self.assertEqual(rc, 1)  # last answer: data zone not locked
        self.assertIn("config zone: LOCKED", out)
        self.assertIn("data zone: unlocked", out)
        # writing config after the lock is refused before touching the chip
        self.assertEqual(self.run_cli("write-config %s" % path)[0], 2)

    def test_write_config_blocks_i2c_address_change(self):
        blob = bytearray(self.sim.config)
        blob[16] = 0xC2
        path = self.put("cfg.bin", bytes(blob))
        rc, _, err = self.run_cli("write-config %s" % path)
        self.assertEqual(rc, 2)
        self.assertIn("I2C address", err)
        self.assertEqual(self.sim.config[16], 0xC0)
        rc, _, _ = self.run_cli("write-config %s" % path, extra=["--allow-i2c-change"])
        self.assertEqual(rc, 0)
        self.assertEqual(self.sim.config[16], 0xC2)

    def test_slot_lock_and_data_lock_need_config_lock(self):
        self.assertEqual(self.run_cli("lock-data", extra=["--yes-lock"])[0], 2)
        self.lock_config()
        self.assertEqual(self.run_cli("lock-slot 3", extra=["--yes-lock"])[0], 0)
        self.assertEqual(self.run_cli("slot-is-locked 3")[0], 0)
        self.assertEqual(self.run_cli("slot-is-locked 4")[0], 1)
        self.assertEqual(self.run_cli("lock-data", extra=["--yes-lock"])[0], 0)
        self.assertTrue(self.sim.data_locked)

    def test_extra(self):
        self.assertEqual(self.run_cli("extra-set 84 7")[0], 0)
        rc, out, _ = self.run_cli("extra-get 84")
        self.assertEqual((rc, out.strip()), (0, "Extra 84: 0x07"))
        self.assertEqual(self.run_cli("extra-set 12 1")[0], 1)


class Counters(Base):
    def test_counter_cycle(self):
        self.assertIn("Counter 0: 0", self.run_cli("counter-read 0")[1])
        self.assertIn("Counter 0: 1", self.run_cli("counter-inc 0")[1])
        self.assertIn("Counter 0: 1", self.run_cli("counter-read 0")[1])
        self.assertIn("Counter 0: %d" % (2097151 - 1), self.run_cli("counter-read 0 -r")[1])

    def test_counter15_init_and_read(self):
        self.assertEqual(self.run_cli("counter-init 15 100")[0], 0)
        self.assertIn("Counter 15: 100", self.run_cli("counter-read 15")[1])
        self.assertIn("Counter 15: 28", self.run_cli("counter-read 15 -r")[1])

    def test_counter_config_encoding(self):
        self.run_cli("counter-init 0 33")
        # lin_a=0xFFFF>>1, lin_b=0xFFFF>>17%32=0xFFFF>>17 -> 0, bin_a=1, bin_b=0
        self.assertEqual(bytes(self.sim.config[52:60]).hex(), "7fff" + "7fff"[:0] + "0000" + "0001" + "0000")


class DataZone(Base):
    def test_plain_write_read_and_hmac_key_block(self):
        self.lock_config()
        payload = bytes(range(36))
        rc, _, _ = self.run_cli("write-data 2 0 %s" % self.put("in", payload))
        self.assertEqual(rc, 0)
        self.assertEqual(bytes(self.sim.data[2]), payload)
        rc, _, _ = self.run_cli("read-data 2 4 20 %s" % self.p("out"))
        self.assertEqual(self.get("out"), payload[4:24])
        key = os.urandom(32)
        self.run_cli("hmac-write-key 5 0 %s" % self.put("k", key))
        self.assertEqual(bytes(self.sim.data[5][:32]), key)
        # big slot 8: multi-block, unaligned read back
        blob = os.urandom(416)
        self.run_cli("write-data 8 0 %s" % self.put("big", blob))
        self.run_cli("read-data 8 30 100 %s" % self.p("o2"))
        self.assertEqual(self.get("o2"), blob[30:130])

    def test_write_past_slot_end_rejected(self):
        self.lock_config()
        rc, _, err = self.run_cli("write-data 1 0 %s" % self.put("in", bytes(40)))
        self.assertEqual(rc, 2)
        self.assertIn("past end", err)

    def test_encrypted_write_and_read(self):
        self.sim.config[20 + 4 * 2] |= 0x40  # slot 4: EncryptRead
        self.lock_config()
        wkey = os.urandom(32)
        self.sim.data[6][:32] = wkey
        self.assertEqual(self.run_cli("lock-data", extra=["--yes-lock"])[0], 0)
        data = os.urandom(32)
        rc, _, err = self.run_cli("hmac-write-key 4 0 %s %s 6" % (self.put("d", data), self.put("wk", wkey)))
        self.assertEqual((rc, err), (0, ""))
        self.assertEqual(bytes(self.sim.data[4][:32]), data)
        rc, _, _ = self.run_cli("read-data 4 0 32 %s %s 6" % (self.p("r"), self.p("wk")))
        self.assertEqual((rc, self.get("r")), (0, data))
        # wrong write key -> chip rejects the MAC, nothing is written
        bad = self.put("bad", os.urandom(32))
        rc, _, err = self.run_cli("hmac-write-key 4 0 %s %s 6" % (self.put("d2", os.urandom(32)), bad))
        self.assertEqual(rc, 2)
        self.assertEqual(bytes(self.sim.data[4][:32]), data)


class Auth(Base):
    def test_password_flow(self):
        self.lock_config()
        pw = self.put("pw", b"s3cret\n")
        self.assertEqual(self.run_cli("auth-make-passwd 7 %s" % pw)[0], 0)
        self.assertEqual(self.run_cli("auth-passwd 7 %s" % pw)[0], 0)
        rc, _, err = self.run_cli("auth-passwd 7 %s" % self.put("bad", b"wrong\n"))
        self.assertEqual(rc, 1)
        self.assertIn("Authentication failure", err)

    def test_check_gendig(self):
        self.lock_config()
        key = os.urandom(32)
        self.sim.data[9][:32] = key
        rc, _, err = self.run_cli("auth-check-gendig 9 %s" % self.put("k", key))
        self.assertEqual((rc, err.strip()), (0, "Keys match"))
        rc, _, err = self.run_cli("auth-check-gendig 9 %s" % self.put("k2", os.urandom(32)))
        self.assertEqual((rc, err.strip()), (1, "Keys doesn't match"))


@unittest.skipUnless(HAVE_CRYPTO, "needs `cryptography` for the simulated ECC engine")
class Ecc(Base):
    def test_gen_sign_verify(self):
        msg = self.put("m", b"hello atecc")
        self.assertEqual(self.run_cli("ecc-gen 0 %s" % self.p("pub"))[0], 0)
        self.assertEqual(len(self.get("pub")), 64)
        self.assertEqual(self.run_cli("ecc-gen-pub 0 %s" % self.p("pub2"))[0], 0)
        self.assertEqual(self.get("pub"), self.get("pub2"))
        self.assertEqual(self.run_cli("ecc-sign 0 %s %s" % (msg, self.p("sig")))[0], 0)
        rc, _, err = self.run_cli("ecc-verify 0 %s %s %s" % (msg, self.p("sig"), self.p("pub")))
        self.assertEqual((rc, err.strip()), (0, "Verification OK"))
        bad = self.put("m2", b"tampered")
        rc, _, err = self.run_cli("ecc-verify 0 %s %s %s" % (bad, self.p("sig"), self.p("pub")))
        self.assertEqual((rc, err.strip()), (1, "Verification FAILED"))

    def test_ecc_write_plain_and_encrypted(self):
        self.lock_config()
        priv = (12345678901234567890).to_bytes(32, "big")
        self.assertEqual(self.run_cli("ecc-write 1 %s" % self.put("pk", priv))[0], 0)
        self.assertIn(1, self.sim.priv)
        wkey = os.urandom(32)
        self.sim.data[3][:32] = wkey
        rc, _, err = self.run_cli("ecc-write 2 %s 3 %s" % (self.put("pk", priv), self.put("wk", wkey)))
        self.assertEqual((rc, err), (0, ""))
        self.assertEqual(self.sim.priv[1].private_numbers().private_value,
                         self.sim.priv[2].private_numbers().private_value)

    def test_stored_pubkey_verify_and_read_pub(self):
        self.lock_config()
        self.run_cli("ecc-gen 0 %s" % self.p("pub"))
        pub = self.get("pub")
        fmt = bytes(4) + pub[:32] + bytes(4) + pub[32:]
        self.sim.data[9][:] = fmt
        self.assertEqual(self.run_cli("ecc-read-pub 9 %s" % self.p("rp"))[0], 0)
        self.assertEqual(self.get("rp"), pub)
        msg = self.put("m", b"stored key")
        self.run_cli("ecc-sign 0 %s %s" % (msg, self.p("sig")))
        rc, _, _ = self.run_cli("ecc-verify 9 %s %s" % (msg, self.p("sig")))
        self.assertEqual(rc, 0)

    def test_ecdh_agreement(self):
        from cryptography.hazmat.primitives.asymmetric import ec
        self.run_cli("ecc-gen 0 %s" % self.p("pub"))
        peer = ec.generate_private_key(ec.SECP256R1())
        n = peer.public_key().public_numbers()
        self.put("peer", n.x.to_bytes(32, "big") + n.y.to_bytes(32, "big"))
        self.assertEqual(self.run_cli("ecdh 0 %s %s" % (self.p("peer"), self.p("pms")))[0], 0)
        mine = ec.EllipticCurvePublicNumbers(
            int.from_bytes(self.get("pub")[:32], "big"), int.from_bytes(self.get("pub")[32:], "big"),
            ec.SECP256R1()).public_key()
        self.assertEqual(self.get("pms"), peer.exchange(ec.ECDH(), mine))

    def test_aes_block(self):
        key = os.urandom(16)
        self.sim.data[5][:16] = key
        pt = os.urandom(16)
        self.run_cli("aes encrypt 5 0 %s %s" % (self.put("pt", pt), self.p("ct")))
        self.run_cli("aes decrypt 5 0 %s %s" % (self.p("ct"), self.p("rt")))
        self.assertNotEqual(self.get("ct"), pt)
        self.assertEqual(self.get("rt"), pt)

    def test_hmac_dgst(self):
        key = os.urandom(32)
        self.sim.data[4][:32] = key
        for size in (0, 5, 64, 100, 200):
            payload = os.urandom(size)
            rc, _, _ = self.run_cli("hmac-dgst 4 %s %s" % (self.put("pl", payload), self.p("h")))
            self.assertEqual(rc, 0)
            self.assertEqual(self.get("h"), hmac.new(key, payload, hashlib.sha256).digest())


class Resilience(Base):
    def test_non_idempotent_command_not_retried_after_lost_response(self):
        chip = Chip(self.sim, retries=3)
        orig = self.sim.read
        state = {"n": 0}

        def flaky(n):
            if n == 4 and state["n"] == 0 and self.sim.out and self.sim.out[0] == 7:
                state["n"] += 1
            return orig(n)
        # Corrupt the single counter-increment response: it must raise, not re-run.
        real_exec = self.sim._execute
        calls = []

        def spy(op, p1, p2, body):
            calls.append(op)
            return real_exec(op, p1, p2, body)
        self.sim._execute = spy
        orig_reply = self.sim._reply

        def bad_reply(data):
            orig_reply(data)
            if len(data) == 4:  # counter value response: break the CRC once
                self.sim.out[-1] ^= 0xFF
                self.sim._reply = orig_reply
        self.sim._reply = bad_reply
        from atecc.errors import CrcError
        with self.assertRaises(CrcError):
            chip.counter_increment(0)
        self.assertEqual(calls.count(0x24), 1)
        self.assertEqual(self.sim.counters[0], 1)

    def test_idempotent_command_is_retried(self):
        chip = Chip(self.sim, retries=3)
        orig_reply = self.sim._reply
        hits = {"n": 0}

        def bad_once(data):
            orig_reply(data)
            if hits["n"] == 0 and len(data) == 4:
                hits["n"] += 1
                self.sim.out[-1] ^= 0xFF
        self.sim._reply = bad_once
        self.sim.counters[0] = 9
        self.assertEqual(chip.counter_read(0), 9)
        self.assertEqual(hits["n"], 1)


class Sha204(Base):
    def test_sha204_config_flow(self):
        self.sim = SimTransport(config=default_config(rev=bytes([0, 2, 0, 9]), size=88), busy_polls=0)
        simmod.SHARED = self.sim
        rc, out, _ = self.run_cli("info", "dump-config -")
        self.assertEqual(rc, 0)
        self.assertIn("ATSHA204A", out)
        self.assertNotIn("KeyConfig", out)
        self.assertEqual(self.run_cli("read-config %s" % self.p("c"))[0], 0)
        self.assertEqual(self.get("c"), bytes(self.sim.config))


if __name__ == "__main__":
    unittest.main()
