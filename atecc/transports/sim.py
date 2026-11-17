"""Software model of a *read-only* ATECC chip, for tests and dry runs.

The default configuration zone is synthetic (not a real factory image).
"""
from ..crc import crc16, crc16_le
from ..errors import NackError
from .base import Transport

WAKE_OK = bytes([0x04, 0x11, 0x33, 0x43])


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


class SimTransport(Transport):
    def __init__(self, config=None, busy_polls=2, addr7=0x60):
        self.addr7 = addr7
        self.config = bytearray(config if config is not None else default_config())
        self.counters = [5, 0]
        self.awake = False
        self.out = bytearray()
        self.busy_polls = busy_polls
        self._busy = 0
        self.log = []

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
            return
        if word != 0x03:
            raise NackError("sim: bad word address")
        cmd = bytes(data[1:])
        count = cmd[0]
        if len(cmd) != count or crc16(cmd[:-2]).to_bytes(2, "little") != cmd[-2:]:
            self._status(0xFF)
            return
        op, p1, p2 = cmd[1], cmd[2], int.from_bytes(cmd[3:5], "little")
        self.log.append((op, p1, p2))
        self._busy = self.busy_polls
        self._execute(op, p1, p2)

    def _execute(self, op, p1, p2):
        if op == 0x30 and p1 == 0:
            self._reply(bytes(self.config[4:8]))
        elif op == 0x02 and (p1 & 0x7F) == 0:
            n = 32 if p1 & 0x80 else 4
            off = ((p2 >> 3) & 0x1F) * 32 + (p2 & 7) * 4
            if off + n > len(self.config):
                self._status(0x0F)
            else:
                self._reply(bytes(self.config[off:off + n]))
        elif op == 0x1B:
            self._reply(bytes(range(32)))
        elif op == 0x24 and p1 == 0 and p2 in (0, 1):
            self._reply(self.counters[p2].to_bytes(4, "little"))
        else:
            self._status(0x03)

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
