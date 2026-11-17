"""CryptoAuth command protocol and the full command set, on top of a Transport.

Command semantics are ported from CryptoAuthLib (wirenboard fork, the version
atecc-util builds against). Host-side session crypto lives in hostcrypto.py.
"""
import os
import time

from . import hostcrypto as hc
from .chips import ChipProfile, detect
from .crc import crc16, crc16_le
from .errors import AteccError, ChipStatusError, CrcError, NackError, TimeoutError_

# word addresses
WA_SLEEP, WA_IDLE, WA_COMMAND = 0x01, 0x02, 0x03

# opcodes
OP_CHECKMAC, OP_DERIVE_KEY, OP_GENDIG, OP_GENKEY = 0x28, 0x1C, 0x15, 0x40
OP_INFO, OP_LOCK, OP_MAC, OP_NONCE, OP_PRIVWRITE = 0x30, 0x17, 0x08, 0x16, 0x46
OP_RANDOM, OP_READ, OP_SIGN, OP_VERIFY, OP_WRITE = 0x1B, 0x02, 0x41, 0x45, 0x12
OP_ECDH, OP_COUNTER, OP_SHA, OP_AES = 0x43, 0x24, 0x47, 0x51
OP_UPDATE_EXTRA, OP_SELFTEST = 0x20, 0x77

ZONE_CONFIG, ZONE_OTP, ZONE_DATA = 0, 1, 2
ZONE_ENCRYPTED, ZONE_32 = 0x40, 0x80

NONCE_TARGET_TEMPKEY, NONCE_TARGET_MSGDIGBUF, NONCE_TARGET_ALTKEYBUF = 0x00, 0x40, 0x80
SIGN_EXTERNAL, SIGN_SRC_MSGDIGBUF = 0x80, 0x20
VERIFY_STORED, VERIFY_EXTERNAL, VERIFY_SRC_MSGDIGBUF = 0x00, 0x02, 0x20
VERIFY_KEY_P256 = 0x0004
GENKEY_PRIVATE, GENKEY_PUBLIC = 0x04, 0x00
LOCK_CONFIG, LOCK_DATA, LOCK_SLOT, LOCK_NO_CRC = 0x00, 0x01, 0x02, 0x80
COUNTER_READ, COUNTER_INCREMENT = 0x00, 0x01
COUNTER_MAX_VALUE = 2097151
SHA_HMAC_START, SHA_HMAC_UPDATE, SHA_608_HMAC_END = 0x04, 0x01, 0x02
SHA_TARGET_TEMPKEY = 0x00
UPDATE_USER_EXTRA, UPDATE_SELECTOR = 0x00, 0x01
PRIVWRITE_ENCRYPT = 0x40
ECDH_PREFIX_MODE = 0x00

WAKE_OK = bytes([0x04, 0x11, 0x33, 0x43])

# Typical execution times in ms (ATECC608A, clock divider M0) from CryptoAuthLib.
# We wait this long before polling; slower clock dividers just poll longer.
EXEC_MS = {
    OP_AES: 27, OP_CHECKMAC: 40, OP_COUNTER: 25, OP_DERIVE_KEY: 50, OP_ECDH: 60,
    OP_GENDIG: 25, OP_GENKEY: 115, OP_INFO: 5, OP_LOCK: 35, OP_MAC: 55, OP_NONCE: 20,
    OP_PRIVWRITE: 50, OP_RANDOM: 23, OP_READ: 5, OP_SELFTEST: 250, OP_SHA: 36,
    OP_SIGN: 115, OP_UPDATE_EXTRA: 10, OP_VERIFY: 105, OP_WRITE: 45,
}
DEFAULT_EXEC_MS = 50


def exec_limits(opcode):
    typical = EXEC_MS.get(opcode, DEFAULT_EXEC_MS)
    return typical, typical * 8 + 1200  # (initial wait, give-up)


def frame(opcode: int, p1: int, p2: int, data: bytes = b"") -> bytes:
    body = bytes([7 + len(data), opcode, p1]) + p2.to_bytes(2, "little") + data
    return bytes([WA_COMMAND]) + body + crc16_le(body)


def get_addr(zone: int, slot: int, block: int, offset: int) -> int:
    offset &= 7
    if (zone & 3) in (ZONE_CONFIG, ZONE_OTP):
        return (block << 3) | offset
    return (slot << 3) | offset | (block << 8)


class Chip:
    def __init__(self, transport, retries: int = 10, profile: ChipProfile = None):
        self.t = transport
        self.retries = retries
        self._profile = profile

    # ---- power states -----------------------------------------------------
    def wake(self):
        self.t.wake_pulse()
        time.sleep(0.003)  # tWHI
        resp = self.t.read(4)
        if resp != WAKE_OK:
            raise ChipStatusError(resp[1] if resp[0] == 4 else 0xFF)

    def idle(self):
        self.t.write(bytes([WA_IDLE]))

    def sleep(self):
        self.t.write(bytes([WA_SLEEP]))

    # ---- command execution ------------------------------------------------
    def _read_response(self, opcode) -> bytes:
        wait_ms, max_ms = exec_limits(opcode)
        time.sleep(wait_ms / 1000.0)
        deadline = time.monotonic() + max_ms / 1000.0
        while True:
            try:
                count = self.t.read(1)[0]
                break
            except NackError:
                if time.monotonic() > deadline:
                    raise TimeoutError_("no response to opcode 0x%02X" % opcode)
                time.sleep(0.001)
        if count < 4:
            raise CrcError("bad response length %d" % count)
        resp = bytes([count]) + (self.t.read(count - 1) if count > 1 else b"")
        if crc16(resp[:-2]).to_bytes(2, "little") != resp[-2:]:
            raise CrcError("response CRC mismatch")
        if count == 4:
            if resp[1] != 0x00:
                raise ChipStatusError(resp[1])
            return b""
        return resp[1:-2]

    def execute(self, opcode, p1, p2, data=b"", idempotent=True) -> bytes:
        """wake -> command -> response -> idle.

        Retries only when it is safe: any failure before the command is delivered,
        and for idempotent commands also lost/corrupt responses. A chip status of
        0xFF (it saw a bad CRC) or 0xEE (watchdog) means nothing ran, so always safe.
        """
        last = None
        pkt = frame(opcode, p1, p2, bytes(data))
        for attempt in range(self.retries + 1):
            sent = False
            try:
                self.wake()
                self.t.write(pkt)
                sent = True
                out = self._read_response(opcode)
                try:
                    self.idle()
                except NackError:
                    pass
                return out
            except (NackError, CrcError, TimeoutError_) as e:
                last = e
                if sent and not idempotent:
                    raise
            except ChipStatusError as e:
                if e.code not in (0xFF, 0xEE):
                    raise
                last = e
            time.sleep(0.01 * (attempt + 1))
        raise last

    def session(self, fn):
        """Run a multi-command sequence (nonce -> gendig -> ...) as a unit and
        retry the whole sequence on transient faults."""
        last = None
        for attempt in range(self.retries + 1):
            try:
                return fn()
            except (NackError, CrcError, TimeoutError_) as e:
                last = e
            except ChipStatusError as e:
                if e.code not in (0xFF, 0xEE):
                    raise
                last = e
            time.sleep(0.01 * (attempt + 1))
        raise last

    def close(self):
        try:
            self.wake()
            self.sleep()
        except Exception:
            pass
        self.t.close()

    # ---- identification ---------------------------------------------------
    def info(self, mode=0x00, param2=0x0000) -> bytes:
        return self.execute(OP_INFO, mode, param2)

    def revision(self) -> bytes:
        return self.info(0x00)

    @property
    def profile(self) -> ChipProfile:
        if self._profile is None:
            self._profile = detect(self.revision())
        return self._profile

    @property
    def is_608(self) -> bool:
        return self.profile.name.startswith("ATECC608")

    # ---- zones ------------------------------------------------------------
    def zone_size(self, zone: int, slot: int = 0) -> int:
        if zone == ZONE_CONFIG:
            return self.profile.config_size
        if zone == ZONE_OTP:
            return 64
        if zone == ZONE_DATA:
            if self.profile.name in ("ATSHA204A", "ATSHA206A"):
                return 32
            if slot < 8:
                return 36
            if slot == 8:
                return 416
            if slot < 16:
                return 72
        raise ValueError("bad zone/slot")

    def read_zone(self, zone, slot, block, offset, length) -> bytes:
        if length not in (4, 32):
            raise ValueError("length must be 4 or 32")
        p1 = zone | (ZONE_32 if length == 32 else 0)
        return self.execute(OP_READ, p1, get_addr(zone, slot, block, offset))

    def read_bytes(self, zone, slot, offset, length) -> bytes:
        if length == 0:
            return b""
        size = self.zone_size(zone, slot)
        if zone == ZONE_DATA and slot > 15:
            raise ValueError("slot must be 0-15")
        if offset + length > size:
            raise ValueError("read past end of zone (%d > %d)" % (offset + length, size))
        out = bytearray()
        cur_block, cur_off, rsize = offset // 32, 0, 32
        while len(out) < length:
            if rsize == 32 and size - cur_block * 32 < 32:
                rsize = 4
                cur_off = ((len(out) + offset) // 4) % 8
            buf = self.read_zone(zone, slot, cur_block, cur_off, rsize)
            read_off = cur_block * 32 + cur_off * 4
            start = offset - read_off if read_off < offset else 0
            take = min(length - len(out), rsize - start)
            out += buf[start:start + take]
            if rsize == 32:
                cur_block += 1
            else:
                cur_off += 1
        return bytes(out)

    def write(self, zone_param, address, value, mac=None):
        data = bytes(value) + (bytes(mac) if mac and (zone_param & ZONE_32) else b"")
        self.execute(OP_WRITE, zone_param, address, data)

    def write_zone(self, zone, slot, block, offset, data):
        if len(data) not in (4, 32):
            raise ValueError("length must be 4 or 32")
        z = zone | (ZONE_32 if len(data) == 32 else 0)
        self.write(z, get_addr(zone, slot, block, offset), data)

    def write_bytes(self, zone, slot, offset, data):
        data = bytes(data)
        if not data:
            return
        if offset % 4 or len(data) % 4:
            raise ValueError("offset and length must be multiples of 4")
        if zone == ZONE_DATA and slot > 15:
            raise ValueError("slot must be 0-15")
        if offset + len(data) > self.zone_size(zone, slot):
            raise ValueError("write past end of zone")
        idx, block, word = 0, offset // 32, (offset % 32) // 4
        while idx < len(data):
            # config block 2 is written word by word: UserExtra/Selector/Lock bytes
            if word == 0 and len(data) - idx >= 32 and not (zone == ZONE_CONFIG and block == 2):
                self.write_zone(zone, slot, block, 0, data[idx:idx + 32])
                idx += 32
                block += 1
            else:
                if not (zone == ZONE_CONFIG and block == 2 and word == 5):
                    self.write_zone(zone, slot, block, word, data[idx:idx + 4])
                idx += 4
                word += 1
                if word == 8:
                    block += 1
                    word = 0

    # ---- config zone helpers ----------------------------------------------
    def read_config(self) -> bytes:
        return self.read_bytes(ZONE_CONFIG, 0, 0, self.profile.config_size)

    def serial(self) -> bytes:
        b = self.read_zone(ZONE_CONFIG, 0, 0, 0, 32)
        return b[0:4] + b[8:13]

    def is_locked(self, zone: str) -> bool:
        w = self.read_zone(ZONE_CONFIG, 0, 2, 5, 4)
        return (w[3] if zone == "config" else w[2]) != 0x55

    def is_slot_locked(self, slot: int) -> bool:
        if not 0 <= slot <= 15:
            raise ValueError("slot must be 0-15")
        w = self.read_zone(ZONE_CONFIG, 0, 2, 6, 4)
        return not ((w[0] | (w[1] << 8)) >> slot) & 1

    def write_config(self, cfg: bytes):
        size = self.profile.config_size
        if len(cfg) != size:
            raise ValueError("config blob must be %d bytes" % size)
        self.write_bytes(ZONE_CONFIG, 0, 16, cfg[16:size])
        self.update_extra(UPDATE_USER_EXTRA, cfg[84])
        self.update_extra(UPDATE_SELECTOR, cfg[85])

    def write_config_counter(self, counter_id: int, value: int):
        if counter_id > 1 or not 0 <= value <= COUNTER_MAX_VALUE:
            raise ValueError("bad counter id/value")
        lin_a = 0xFFFF >> (value % 32)
        lin_b = 0xFFFF >> (((value - 16) % 32) if value >= 16 else 0)
        bin_a = value // 32
        bin_b = ((value - 16) // 32) if value >= 16 else 0
        raw = b"".join(x.to_bytes(2, "big") for x in (lin_a, lin_b, bin_a, bin_b))
        self.write_bytes(ZONE_CONFIG, 0, 52 + counter_id * 8, raw)

    def update_extra(self, mode: int, value: int):
        self.execute(OP_UPDATE_EXTRA, mode, value & 0xFFFF, idempotent=False)

    # ---- lock -------------------------------------------------------------
    def lock(self, mode: int, crc: int = 0):
        self.execute(OP_LOCK, mode, crc, idempotent=False)

    def lock_config(self):
        self.lock(LOCK_NO_CRC | LOCK_CONFIG)

    def lock_data(self):
        self.lock(LOCK_NO_CRC | LOCK_DATA)

    def lock_slot(self, slot: int):
        self.lock(((slot & 0xFF) << 2) | LOCK_SLOT)

    # ---- random / counters ------------------------------------------------
    def random(self) -> bytes:
        out = self.execute(OP_RANDOM, 0x00, 0x0000)
        if len(out) != 32:
            raise CrcError("random response has %d bytes" % len(out))
        return out

    def counter_read(self, cid: int) -> int:
        if cid not in (0, 1):
            raise ValueError("counter id must be 0 or 1")
        return int.from_bytes(self.execute(OP_COUNTER, COUNTER_READ, cid)[:4], "little")

    def counter_increment(self, cid: int) -> int:
        if cid not in (0, 1):
            raise ValueError("counter id must be 0 or 1")
        return int.from_bytes(
            self.execute(OP_COUNTER, COUNTER_INCREMENT, cid, idempotent=False)[:4], "little")

    # ---- nonce / gendig / checkmac ---------------------------------------
    def nonce_rand(self, num_in: bytes) -> bytes:
        return self.execute(OP_NONCE, 0x00, 0x0000, num_in)

    def nonce_load(self, target: int, data: bytes):
        if len(data) not in (32, 64):
            raise ValueError("nonce input must be 32 or 64 bytes")
        mode = 0x03 | (target & 0xC0) | (0x20 if len(data) == 64 else 0)
        self.execute(OP_NONCE, mode, 0x0000, data)

    def gendig(self, zone: int, key_id: int, other_data: bytes = b""):
        data = b""
        if zone == 3 and len(other_data) >= 32:
            data = other_data[:32]
        elif zone == 2 and len(other_data) >= 4:
            data = other_data[:4]
        self.execute(OP_GENDIG, zone, key_id, data)

    def checkmac(self, mode: int, key_id: int, challenge, response: bytes, other_data: bytes):
        if len(response) != 32 or len(other_data) != 13:
            raise ValueError("response must be 32 and other_data 13 bytes")
        self.execute(OP_CHECKMAC, mode, key_id, (challenge or bytes(32)) + response + other_data)

    def mac(self, mode: int, key_id: int, challenge: bytes = b"") -> bytes:
        return self.execute(OP_MAC, mode, key_id, challenge if not mode & 0x01 else b"")

    def derive_key(self, mode: int, target: int, mac: bytes = None):
        self.execute(OP_DERIVE_KEY, mode, target, mac or b"", idempotent=False)

    def selftest(self, mode: int = 0x3F):
        self.execute(OP_SELFTEST, mode, 0x0000)

    def aes(self, mode: int, key_id: int, block16: bytes) -> bytes:
        if len(block16) != 16:
            raise ValueError("AES block must be 16 bytes")
        return self.execute(OP_AES, mode, key_id, block16)

    # ---- session helpers (nonce + gendig on both sides) --------------------
    def _tempkey_from_slot(self, key_slot: int, key: bytes):
        sn = self.read_zone(ZONE_CONFIG, 0, 0, 0, 32)
        sn = sn[0:4] + sn[8:13]
        num_in = os.urandom(20)
        rand_out = self.nonce_rand(num_in)
        tk = hc.nonce_random(num_in, rand_out)
        other = bytes([OP_GENDIG, hc.GENDIG_ZONE_DATA, key_slot & 0xFF, key_slot >> 8])
        self.gendig(hc.GENDIG_ZONE_DATA, key_slot, other)
        return sn, hc.gen_dig_data(sn, key_slot, key, tk)

    # ---- encrypted data I/O ------------------------------------------------
    def read_enc(self, key_id: int, block: int, enc_key: bytes, enc_key_id: int) -> bytes:
        def run():
            _, tk = self._tempkey_from_slot(enc_key_id, enc_key)
            raw = self.read_zone(ZONE_DATA, key_id, block, 0, 32)
            return bytes(a ^ b for a, b in zip(raw, tk.value))
        return self.session(run)

    def write_enc(self, key_id: int, block: int, data: bytes, enc_key: bytes, enc_key_id: int):
        if len(data) != 32:
            raise ValueError("data must be 32 bytes")

        def run():
            sn, tk = self._tempkey_from_slot(enc_key_id, enc_key)
            addr = get_addr(ZONE_DATA, key_id, block, 0)
            zone = ZONE_DATA | ZONE_32 | ZONE_ENCRYPTED
            cipher, mac = hc.write_auth(tk, sn, zone, addr, data)
            self.write(zone, addr, cipher, mac)
        self.session(run)

    # ---- keys / ECC ---------------------------------------------------------
    def genkey(self, key_id: int) -> bytes:
        return self.execute(OP_GENKEY, GENKEY_PRIVATE, key_id, idempotent=False)

    def get_pubkey(self, key_id: int) -> bytes:
        return self.execute(OP_GENKEY, GENKEY_PUBLIC, key_id)

    def read_pubkey(self, slot: int) -> bytes:
        if not 8 <= slot <= 15:
            raise ValueError("public keys live in slots 8-15")
        b0 = self.read_zone(ZONE_DATA, slot, 0, 0, 32)
        b1 = self.read_zone(ZONE_DATA, slot, 1, 0, 32)
        b2 = self.read_zone(ZONE_DATA, slot, 2, 0, 32)
        return b0[4:32] + b1[0:4] + b1[8:32] + b2[0:8]

    def write_pubkey(self, slot: int, pub64: bytes):
        if len(pub64) != 64:
            raise ValueError("public key must be 64 bytes")
        fmt = bytes(4) + pub64[:32] + bytes(4) + pub64[32:]
        self.write_bytes(ZONE_DATA, slot, 0, fmt)

    def priv_write(self, key_id: int, key32: bytes, write_key: bytes = None, write_key_id: int = None):
        if key_id > 15 or len(key32) != 32:
            raise ValueError("bad key id or key length")
        payload = bytes(4) + key32  # chip expects 36 bytes with 4 leading zeros
        if write_key is None:
            self.execute(OP_PRIVWRITE, 0x00, key_id, payload + bytes(32))
            return

        def run():
            sn, tk = self._tempkey_from_slot(write_key_id, write_key)
            cipher, mac = hc.privwrite_auth(tk, sn, key_id, payload, PRIVWRITE_ENCRYPT)
            self.execute(OP_PRIVWRITE, PRIVWRITE_ENCRYPT, key_id, cipher + mac)
        self.session(run)

    def _digest_target(self):
        if self.is_608:
            return NONCE_TARGET_MSGDIGBUF, SIGN_SRC_MSGDIGBUF, VERIFY_SRC_MSGDIGBUF
        return NONCE_TARGET_TEMPKEY, 0x00, 0x00

    def sign(self, key_id: int, digest: bytes) -> bytes:
        if len(digest) != 32:
            raise ValueError("digest must be 32 bytes")
        nt, ss, _ = self._digest_target()

        def run():
            self.random()  # refreshes RNG seed, as CryptoAuthLib does before external sign
            self.nonce_load(nt, digest)
            return self.execute(OP_SIGN, SIGN_EXTERNAL | ss, key_id)
        return self.session(run)

    def _verify(self, mode_base, key_id, digest, sig, pub=None) -> bool:
        nt, _, vs = self._digest_target()

        def run():
            self.nonce_load(nt, digest)
            try:
                self.execute(OP_VERIFY, mode_base | vs, key_id, sig + (pub or b""))
            except ChipStatusError as e:
                if e.code == 0x01:
                    return False
                raise
            return True
        return self.session(run)

    def verify_stored(self, digest: bytes, sig: bytes, slot: int) -> bool:
        return self._verify(VERIFY_STORED, slot, digest, sig)

    def verify_extern(self, digest: bytes, sig: bytes, pub64: bytes) -> bool:
        return self._verify(VERIFY_EXTERNAL, VERIFY_KEY_P256, digest, sig, pub64)

    def ecdh(self, slot: int, pub64: bytes) -> bytes:
        if len(pub64) != 64:
            raise ValueError("public key must be 64 bytes")
        return self.execute(OP_ECDH, ECDH_PREFIX_MODE, slot, pub64)[:32]

    # ---- HMAC (SHA command, ATECC608 only) ---------------------------------
    def hmac(self, key_slot: int, data: bytes) -> bytes:
        if not self.is_608:
            raise AteccError("SHA-command HMAC needs an ATECC608")
        data = bytes(data)

        def run():
            self.execute(OP_SHA, SHA_HMAC_START, key_slot)
            pos = 0
            while len(data) - pos >= 64:
                self.execute(OP_SHA, SHA_HMAC_UPDATE, 64, data[pos:pos + 64])
                pos += 64
            tail = data[pos:]
            return self.execute(OP_SHA, SHA_608_HMAC_END | SHA_TARGET_TEMPKEY, len(tail), tail)
        return self.session(run)

    # ---- authentication ------------------------------------------------------
    def auth_password(self, slot: int, key: bytes) -> bool:
        """CheckMac mode 1 against the key stored in `slot`. False on mismatch."""
        other = bytes(13)

        def run():
            sn = self.read_zone(ZONE_CONFIG, 0, 0, 0, 32)
            sn = sn[0:4] + sn[8:13]
            num_in = os.urandom(20)
            tk = hc.nonce_random(num_in, self.nonce_rand(num_in))
            resp = hc.check_mac_response(1, key, None, other, sn, tk)
            try:
                self.checkmac(1, slot, None, resp, other)
            except ChipStatusError as e:
                if e.code == 0x01:
                    return False
                raise
            return True
        return self.session(run)

    def auth_check_gendig(self, slot: int, key: bytes) -> bool:
        """GenDig + CheckMac mode 2: True when the stored key equals `key`."""
        def run():
            challenge = self.random()
            sn, tk = self._tempkey_from_slot(slot, key)
            other = bytes([OP_GENDIG, hc.GENDIG_ZONE_DATA, slot & 0xFF, slot >> 8]) + bytes(9)
            resp = hc.check_mac_response(2, key, challenge, other, sn, tk)
            try:
                self.checkmac(2, 0, challenge, resp, other)
            except ChipStatusError as e:
                if e.code == 0x01:
                    return False
                raise
            return True
        return self.session(run)
