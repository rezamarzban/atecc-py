class Transport:
    """Raw I2C access to one chip. `addr7` is the 7-bit I2C address."""

    addr7 = 0x60

    def wake_pulse(self) -> None:
        """Write to address 0x00 so SDA is held low long enough to wake the chip.
        The write is expected to be NACKed; implementations must swallow that."""
        raise NotImplementedError

    def write(self, data: bytes) -> None:
        """Write `data` to the chip. Raise NackError if not acknowledged."""
        raise NotImplementedError

    def read(self, n: int) -> bytes:
        """Read exactly `n` bytes. Raise NackError if not acknowledged."""
        raise NotImplementedError

    def close(self) -> None:
        pass
