"""Software model of an ATECC/ATSHA chip for tests and dry runs.

Implements the command set with real semantics where it matters for the host
code (zones, locks, nonce/gendig/checkmac, encrypted writes, counters). ECC and
AES commands need the optional `cryptography` package; without it they answer
with a parse-error status. The default configuration zone is synthetic.
"""
import hashlib
import hmac as _hmac
import os

from .. import hostcrypto as hc
from ..crc import crc16, crc16_le
from ..errors import NackError
from .base import Transport

WAKE_OK = bytes([0x04, 0x11, 0x33, 0x43])
SHARED = None  # tests may set a SimTransport here so several CLI runs share state


class Status(Exception):
    def __init__(self, code):
        self.code = code


def default_config(rev=bytes([0x00, 0x00, 0x60, 0x02]), size=128) -> bytearray:
    cfg = bytearray(size)
    cfg[0:4] = bytes([0x01, 0x23, 0xAA, 0xBB])
    cfg[4:8] = rev
    cfg[8:13] = bytes([0x11, 0x22, 0x33, 0x44, 0xEE])
    cfg[16] = 0xC0
    for slot in range(16):
        cfg[20 + slot * 2: 22 + slot * 2] = bytes([0x8F, 0x20])
    cfg[86] = 0x55
    cfg[87] = 0x55
    if size == 128:
        cfg[88:90] = b"\xff\xff"
        for slot in range(16):
            cfg[96 + slot * 2: 98 + slot * 2] = bytes([0x13, 0x00])
    return cfg


def _ec():
    try:
        from cryptography.hazmat.primitives.asymmetric import ec
        return ec
    except ImportError:
        raise Status(0x03)


class SimTransport(Transport):
    def __init__(self, config=None, busy_polls=2, addr7=0x60):
        self.addr7 = addr7
        self.config = bytearray(config if config is not None else default_config())
        self.sha204 = len(self.config) == 88
        self.otp = bytearray(64)
        self.data = {s: bytearray(self._slot_size(s)) for s in range(16)}
        self.priv = {}
        self.counters = [0, 0]
        self.tempkey = hc.TempKey()
        self.msgdigbuf = b""
        self.altkeybuf = b""
        self._hmac = None
        self.awake = False
        self.out = bytearray()
        self.busy_polls = busy_polls
        self._busy = 0
        self.log = []

    # ---- helpers -------------------------------------------------------------
    def _slot_size(self, s):
        if self.sha204:
            return 32
        return 36 if s < 8 else 416 if s == 8 else 72

    @property
    def sn(self):
        return bytes(self.config[0:4] + self.config[8:13])

    @property
    def config_locked(self):
        return self.config[87] != 0x55

    @property
    def data_locked(self):
        return self.config[86] != 0x55

    def _zone_mem(self, zone, p2):
        if zone == 0:
            return self.config, ((p2 >> 3) & 0x1F) * 32 + (p2 & 7) * 4, None
        if zone == 1:
            return self.otp, ((p2 >> 3) & 0x1F) * 32 + (p2 & 7) * 4, None
        slot, block, word = (p2 >> 3) & 0xF, (p2 >> 8) & 0xF, p2 & 7
        return self.data[slot], block * 32 + word * 4, slot

    # ---- transport -------------------------------------------------------------
    def wake_pulse(self):
        self.awake = True
        self.out = bytearray(WAKE_OK)
        self._busy = 0

    def _reply(self, data: bytes):
        body = bytes([len(data) + 3]) + data
        self.out = bytearray(body + crc16_le(body))

    def _status(self, code):
        self._reply(bytes([code]))

    def write(self, data):
        if not self.awake:
            raise NackError("sim: asleep")
        word = data[0]
        if word in (0x01, 0x02):
            self.awake = False
            self.out = bytearray()
            if word == 0x01:  # sleep clears volatile state
                self.tempkey = hc.TempKey()
                self.msgdigbuf = b""
            return
        if word != 0x03:
            raise NackError("sim: bad word address")
        cmd = bytes(data[1:])
        count = cmd[0]
        if len(cmd) != count or crc16(cmd[:-2]).to_bytes(2, "little") != cmd[-2:]:
            self._status(0xFF)
            return
        op, p1, p2, body = cmd[1], cmd[2], int.from_bytes(cmd[3:5], "little"), cmd[5:-2]
        self.log.append((op, p1, p2, bytes(body)))
        self._busy = self.busy_polls
        try:
            out = self._execute(op, p1, p2, body)
            self._reply(out) if out else self._status(0x00)
        except Status as s:
            self._status(s.code)

    def read(self, n):
        if not self.awake:
            raise NackError("sim: asleep")
        if self._busy > 0:
            self._busy -= 1
            raise NackError("sim: busy")
        if len(self.out) < n:
            raise NackError("sim: nothing to read")
        data, self.out = bytes(self.out[:n]), self.out[n:]
        return data

    # ---- command set -------------------------------------------------------------
    def _execute(self, op, p1, p2, body):
        fn = {0x30: self._info, 0x02: self._read, 0x12: self._write, 0x17: self._lock,
              0x1B: self._random, 0x24: self._counter, 0x16: self._nonce, 0x15: self._gendig,
              0x28: self._checkmac, 0x20: self._update_extra, 0x40: self._genkey,
              0x46: self._privwrite, 0x41: self._sign, 0x45: self._verify, 0x43: self._ecdh,
              0x47: self._sha, 0x77: lambda *a: b"", 0x51: self._aes}.get(op)
        if fn is None:
            raise Status(0x03)
        return fn(p1, p2, body)

    def _info(self, p1, p2, body):
        if p1 != 0:
            raise Status(0x03)
        return bytes(self.config[4:8])

    def _read(self, p1, p2, body):
        zone = p1 & 3
        mem, off, slot = self._zone_mem(zone, p2)
        n = 32 if p1 & 0x80 else 4
        if slot in self.priv or off >= len(mem):
            raise Status(0x0F)
        if off + n > len(mem) and zone != 2:
            raise Status(0x0F)
        out = bytes(mem[off:off + n]).ljust(n, b"\x00")  # last block of a data slot may be partial
        if zone == 2 and self.data_locked and self.config[20 + slot * 2] & 0x40:
            if not self.tempkey.valid or n != 32:
                raise Status(0x0F)
            out = bytes(a ^ b for a, b in zip(out, self.tempkey.value))
            self.tempkey = hc.TempKey()
        return out

    def _write(self, p1, p2, body):
        zone = p1 & 3
        mem, off, slot = self._zone_mem(zone, p2)
        n = 32 if p1 & 0x80 else 4
        if zone == 0:
            if self.config_locked or off < 16 or off + n > len(mem) or any(
                    o in range(84, 88) for o in range(off, off + n)):
                raise Status(0x0F)
        elif not self.config_locked or off + n > len(mem):
            raise Status(0x0F)
        elif self.data_locked and not p1 & 0x40:
            raise Status(0x0F)
        if p1 & 0x40:
            cipher, mac = body[:32], body[32:64]
            tk = self.tempkey
            if len(body) != 64 or not tk.valid:
                raise Status(0x0F)
            plain = bytes(a ^ b for a, b in zip(cipher, tk.value))
            if hc.write_auth(tk, self.sn, p1, p2, plain)[1] != mac:
                raise Status(0x01)
            self.tempkey = hc.TempKey()
            body = plain
        if len(body) != n:
            raise Status(0x03)
        mem[off:off + n] = body

    def _lock(self, p1, p2, body):
        zone = p1 & 3
        if zone != 2 and not p1 & 0x80:
            raise Status(0x01)  # CRC-summary locks are not modelled
        if zone == 0:
            if self.config_locked:
                raise Status(0x0F)
            self.config[87] = 0x00
        elif zone == 1:
            if not self.config_locked or self.data_locked:
                raise Status(0x0F)
            self.config[86] = 0x00
        elif zone == 2:
            slot = (p1 >> 2) & 0xF
            self.config[88 + (slot // 8)] &= ~(1 << (slot % 8)) & 0xFF
        else:
            raise Status(0x03)

    def _random(self, p1, p2, body):
        return os.urandom(32)

    def _counter(self, p1, p2, body):
        if p2 not in (0, 1) or p1 not in (0, 1):
            raise Status(0x03)
        if p1 == 1:
            self.counters[p2] += 1
        return self.counters[p2].to_bytes(4, "little")

    def _update_extra(self, p1, p2, body):
        idx = 84 + (p1 & 1)
        if self.config[idx] not in (0, p2 & 0xFF) and p2 != 0:
            raise Status(0x0F)
        self.config[idx] = p2 & 0xFF

    def _nonce(self, p1, p2, body):
        if p1 & 3 in (0, 1):
            if len(body) != 20:
                raise Status(0x03)
            rand = os.urandom(32)
            self.tempkey = hc.nonce_random(body, rand, p1)
            return rand
        if p1 & 3 == 3:
            if len(body) not in (32, 64):
                raise Status(0x03)
            target = p1 & 0xC0
            if target == 0x00:
                self.tempkey = hc.TempKey(value=body[:32], valid=True, source_flag=1)
            elif target == 0x40:
                self.msgdigbuf = body[:32]
            else:
                self.altkeybuf = body[:32]
            return b""
        raise Status(0x03)

    def _slot_key(self, slot):
        return bytes(self.data[slot][:32])

    def _gendig(self, p1, p2, body):
        if p1 != 2 or not self.tempkey.valid:
            raise Status(0x0F)
        self.tempkey = hc.gen_dig_data(self.sn, p2, self._slot_key(p2), self.tempkey)

    def _checkmac(self, p1, p2, body):
        if len(body) != 77:
            raise Status(0x03)
        chal, resp, other = body[:32], body[32:64], body[64:77]
        slot_key = bytes(32) if p1 & 2 else self._slot_key(p2)
        try:
            want = hc.check_mac_response(p1, slot_key, chal, other, self.sn, self.tempkey)
        except ValueError:
            raise Status(0x0F)
        if want != resp:
            raise Status(0x01)

    # ---- ECC / AES / SHA (need `cryptography`) ------------------------------------
    @staticmethod
    def _pub_bytes(priv):
        n = priv.public_key().public_numbers()
        return n.x.to_bytes(32, "big") + n.y.to_bytes(32, "big")

    def _genkey(self, p1, p2, body):
        ec = _ec()
        if p1 == 0x04:
            self.priv[p2] = ec.generate_private_key(ec.SECP256R1())
            return self._pub_bytes(self.priv[p2])
        if p1 == 0x00 and p2 in self.priv:
            return self._pub_bytes(self.priv[p2])
        raise Status(0x0F)

    def _privwrite(self, p1, p2, body):
        ec = _ec()
        if p1 & 0x40:
            tk = self.tempkey
            if not tk.valid or len(body) != 68:
                raise Status(0x0F)
            key2 = hc.sha256(tk.value)
            plain = (bytes(a ^ b for a, b in zip(body[:32], tk.value))
                     + bytes(a ^ b for a, b in zip(body[32:36], key2[:4])))
            if hc.privwrite_auth(tk, self.sn, p2, plain, p1)[1] != body[36:68]:
                raise Status(0x01)
            self.tempkey = hc.TempKey()
        else:
            if len(body) != 68:
                raise Status(0x03)
            plain = body[:36]
        self.priv[p2] = ec.derive_private_key(int.from_bytes(plain[4:36], "big"), ec.SECP256R1())

    def _digest(self, p1):
        return self.msgdigbuf if p1 & 0x20 else self.tempkey.value

    def _sign(self, p1, p2, body):
        ec = _ec()
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import utils
        if p2 not in self.priv:
            raise Status(0x0F)
        der = self.priv[p2].sign(self._digest(p1), ec.ECDSA(utils.Prehashed(hashes.SHA256())))
        r, s = utils.decode_dss_signature(der)
        return r.to_bytes(32, "big") + s.to_bytes(32, "big")

    def _verify(self, p1, p2, body):
        ec = _ec()
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import utils
        sig = body[:64]
        if p1 & 3 == 2:
            pub = body[64:128]
        else:
            d = bytes(self.data[p2])
            pub = d[4:36] + d[40:72]
        try:
            key = ec.EllipticCurvePublicNumbers(
                int.from_bytes(pub[:32], "big"), int.from_bytes(pub[32:], "big"),
                ec.SECP256R1()).public_key()
            key.verify(utils.encode_dss_signature(int.from_bytes(sig[:32], "big"),
                                                  int.from_bytes(sig[32:], "big")),
                       self._digest(p1), ec.ECDSA(utils.Prehashed(hashes.SHA256())))
        except (InvalidSignature, ValueError):
            raise Status(0x01)

    def _ecdh(self, p1, p2, body):
        ec = _ec()
        if p2 not in self.priv or len(body) != 64:
            raise Status(0x0F)
        peer = ec.EllipticCurvePublicNumbers(
            int.from_bytes(body[:32], "big"), int.from_bytes(body[32:], "big"),
            ec.SECP256R1()).public_key()
        return self.priv[p2].exchange(ec.ECDH(), peer)

    def _sha(self, p1, p2, body):
        mode = p1 & 7
        if mode == 4:
            self._hmac = (self._slot_key(p2), bytearray())
            return b""
        if self._hmac is None:
            raise Status(0x0F)
        key, buf = self._hmac
        buf += body
        if mode == 1:
            return b""
        if mode == 2:
            self._hmac = None
            return _hmac.new(key, bytes(buf), hashlib.sha256).digest()
        raise Status(0x03)

    def _aes(self, p1, p2, body):
        try:
            from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        except ImportError:
            raise Status(0x03)
        if len(body) != 16:
            raise Status(0x03)
        key = bytes(self.data[p2][:16])
        c = Cipher(algorithms.AES(key), modes.ECB())
        op = c.encryptor() if (p1 & 0x3F) == 0 else c.decryptor()
        return op.update(body) + op.finalize()
