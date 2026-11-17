"""Host session crypto vs. vectors produced by the real CryptoAuthLib C code
(atca_host.c, wirenboard fork 590807a) for the same inputs."""
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from atecc import hostcrypto as h

b = bytes.fromhex
NUM_IN = b("000102030405060708090a0b0c0d0e0f10111213")
RAND = b("a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf")
SN = b("0123056274aab8f8ee")
KEY = b("1112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f30")
PLAIN = b("c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf")
CHAL = b("e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")
PRIV = bytes(0 if i < 4 else (i * 7 + 3) & 0xFF for i in range(36))
OTHER = bytes((i * 3 + 1) for i in range(13))


class Vectors(unittest.TestCase):
    def test_all(self):
        nonce = h.nonce_random(NUM_IN, RAND)
        self.assertEqual(nonce.value.hex(), "bee176f91b7f8d191759f8a596f2065d6805a5cf831563b7d512574ec54a3169")
        tk = h.gen_dig_data(SN, 5, KEY, nonce)
        self.assertEqual(tk.value.hex(), "f90e74653719cdf1957664372ba71609187dbea3f899d70e2c0d73d503b212ed")
        c, m = h.write_auth(tk, SN, 0x02 | 0x80 | 0x40, (3 << 8) | (9 << 3), PLAIN)
        self.assertEqual(c.hex(), "39cfb6a6f3dc0b365dbfaefce76ad8c6c8ac6c702c4c01d9f4d4a90edf6fcc32")
        self.assertEqual(m.hex(), "59fd7255fe63c2d7b0329de09c801439e7062431684f2f919a6362a4bff80e69")
        c, m = h.privwrite_auth(tk, SN, 7, PRIV)
        self.assertEqual(c.hex(), "f90e7465283fe0c5ae342d677cf973656b073f2b770f4aaa87bfca15c47cc731b14f468f")
        self.assertEqual(m.hex(), "225c3c37bdc7784d62509e963846790cf9815b4e6cd5949d9a68a4ea9000d697")
        self.assertEqual(h.check_mac_response(1, KEY, None, OTHER, SN, nonce).hex(),
                         "963b89979128485b223d1e29e9022980f6f103a04ff1e5610d07df90869ee191")
        self.assertEqual(h.check_mac_response(2, KEY, CHAL, OTHER, SN, nonce).hex(),
                         "4343a3a960b1f780dff1d59d44e02bcfbf38af43288427942bc0dce9d5809ef5")


if __name__ == "__main__":
    unittest.main()
