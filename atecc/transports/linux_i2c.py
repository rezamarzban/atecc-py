"""/dev/i2c-N backend (plain Linux, or Termux with the LD_PRELOAD shim)."""
import fcntl
import os

from ..errors import NackError
from .base import Transport

I2C_SLAVE = 0x0703


class LinuxI2C(Transport):
    def __init__(self, bus: int, addr7: int):
        self.addr7 = addr7
        self.fd = os.open("/dev/i2c-%d" % bus, os.O_RDWR)
        fcntl.ioctl(self.fd, I2C_SLAVE, addr7)

    def wake_pulse(self):
        try:
            fcntl.ioctl(self.fd, I2C_SLAVE, 0x00)
            os.write(self.fd, b"\x00")
        except OSError:
            pass  # NACK is expected
        finally:
            fcntl.ioctl(self.fd, I2C_SLAVE, self.addr7)

    def write(self, data):
        try:
            n = os.write(self.fd, bytes(data))
        except OSError as e:
            raise NackError("write failed: %s" % e)
        if n != len(data):
            raise NackError("short write")

    def read(self, n):
        try:
            out = os.read(self.fd, n)
        except OSError as e:
            raise NackError("read failed: %s" % e)
        if len(out) != n:
            raise NackError("short read")
        return out

    def close(self):
        os.close(self.fd)
