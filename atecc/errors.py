class AteccError(Exception):
    """Base class for all errors raised by this package."""


class NackError(AteccError):
    """The chip did not acknowledge (asleep, busy, or wrong address)."""


class CrcError(AteccError):
    """Response CRC did not match."""


class TimeoutError_(AteccError):
    """Chip never became ready to return a response."""


STATUS_NAMES = {
    0x01: "checkmac/verify miscompare",
    0x03: "parse error (bad opcode/params/length)",
    0x05: "ECC fault",
    0x07: "self-test error",
    0x08: "health-test error (RNG)",
    0x0F: "execution error (command not allowed in current state/config)",
    0x11: "wake received (unexpected here)",
    0xEE: "watchdog about to expire",
    0xFF: "CRC / communication error",
}


class ChipStatusError(AteccError):
    def __init__(self, code: int):
        self.code = code
        super().__init__(
            "chip returned status 0x%02X: %s" % (code, STATUS_NAMES.get(code, "unknown"))
        )
