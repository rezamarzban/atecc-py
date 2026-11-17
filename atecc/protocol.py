"""CryptoAuth command protocol on top of a Transport."""
import time

from .chips import ChipProfile, detect
from .crc import crc16, crc16_le
from .errors import ChipStatusError, CrcError, NackError, TimeoutError_

# word addresses
WA_SLEEP, WA_IDLE, WA_COMMAND = 0x01, 0x02, 0x03

# opcodes
OP_READ, OP_INFO, OP_RANDOM, OP_COUNTER = 0x02, 0x30, 0x1B, 0x24

ZONE_CONFIG, ZONE_OTP, ZONE_DATA = 0, 1, 2

WAKE_OK = bytes([0x04, 0x11, 0x33, 0x43])

# (minimum wait before polling in ms, give-up time in ms)
EXEC_MS = {
    OP_INFO: (2, 500), OP_READ: (2, 500), OP_RANDOM: (10, 1000), OP_COUNTER: (10, 1000),
}
DEFAULT_EXEC_MS = (10, 2000)


def frame(opcode: int, p1: int, p2: int, data: bytes = b"") -> bytes:
    body = bytes([7 + len(data), opcode, p1]) + p2.to_bytes(2, "little") + data
    return bytes([WA_COMMAND]) + body + crc16_le(body)


class Chip:
    def __init__(self, transport, retries: int = 10, profile: ChipProfile = None):
        self.t = transport
        self.retries = retries
        self._profile = profile

    # -- power states ---------------------------------------------------
    def wake(self):
        self.t.wake_pulse()
        time.sleep(0.003)  # tWHI
        resp = self.t.read(4)
        if resp != WAKE_OK:
            raise ChipStatusError(resp[1] if len(resp) > 1 and resp[0] == 4 else 0xFF)

    def idle(self):
        self.t.write(bytes([WA_IDLE]))

    def sleep(self):
        self.t.write(bytes([WA_SLEEP]))

    # -- command execution ---------------------------------------------
    def _read_response(self, opcode) -> bytes:
        min_ms, max_ms = EXEC_MS.get(opcode, DEFAULT_EXEC_MS)
        time.sleep(min_ms / 1000.0)
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
        rest = self.t.read(count - 1) if count > 1 else b""
        resp = bytes([count]) + rest
        if crc16(resp[:-2]).to_bytes(2, "little") != resp[-2:]:
            raise CrcError("response CRC mismatch")
        if count == 4:
            code = resp[1]
            if code != 0x00:
                raise ChipStatusError(code)
            return b""
        return resp[1:-2]

    def execute(self, opcode: int, p1: int, p2: int, data: bytes = b"") -> bytes:
        """wake -> command -> response -> idle, with retries on transient faults."""
        last = None
        for attempt in range(self.retries + 1):
            try:
                self.wake()
                self.t.write(frame(opcode, p1, p2, data))
                out = self._read_response(opcode)
                try:
                    self.idle()
                except NackError:
                    pass
                return out
            except (NackError, CrcError, TimeoutError_) as e:
                last = e
            except ChipStatusError as e:
                # Only comm-level faults are worth retrying; the rest are definitive.
                if e.code not in (0xFF, 0xEE):
                    raise
                last = e
            time.sleep(0.01 * (attempt + 1))
        raise last

    def close(self):
        try:
            self.wake()
            self.sleep()  # park the chip: clears latched fault states
        except Exception:
            pass
        self.t.close()

    # -- commands -------------------------------------------------------
    def revision(self) -> bytes:
        return self.execute(OP_INFO, 0x00, 0x0000)

    @property
    def profile(self) -> ChipProfile:
        if self._profile is None:
            self._profile = detect(self.revision())
        return self._profile

    def read(self, zone: int, address: int, length: int) -> bytes:
        if length not in (4, 32):
            raise ValueError("length must be 4 or 32")
        p1 = zone | (0x80 if length == 32 else 0)
        return self.execute(OP_READ, p1, address)

    def read_config(self) -> bytes:
        size = self.profile.config_size
        out = b""
        while len(out) < size:
            off = len(out)
            block, word = off // 32, (off % 32) // 4
            if off + 32 <= size and word == 0:
                out += self.read(ZONE_CONFIG, block << 3, 32)
            else:
                out += self.read(ZONE_CONFIG, (block << 3) | word, 4)
        return out

    def serial(self) -> bytes:
        a = self.read(ZONE_CONFIG, 0, 4)
        b = self.read(ZONE_CONFIG, 2, 4)  # bytes 8..11
        c = self.read(ZONE_CONFIG, 3, 4)  # bytes 12..15
        return a + b + c[:1]

    def counter_read(self, counter_id: int) -> int:
        if counter_id not in self.profile.counters:
            raise ValueError("%s has no counter %d" % (self.profile.name, counter_id))
        return int.from_bytes(self.execute(OP_COUNTER, 0x00, counter_id), "little")

    def random(self) -> bytes:
        return self.execute(OP_RANDOM, 0x00, 0x0000)
