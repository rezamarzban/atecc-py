"""Python port of the i2cshim.c LD_PRELOAD shim.

Talks I2C-Tiny-USB directly over the USB file descriptor that `termux-usb`
hands to its callback, using libusb through ctypes. No LD_PRELOAD, no compiler.
Requires only:  pkg install libusb
"""
import ctypes
import ctypes.util
import os

from ..errors import AteccError, NackError
from .base import Transport

# i2c-tiny-usb protocol
CMD_GET_FUNC = 1
CMD_SET_DELAY = 2
CMD_GET_STATUS = 3
CMD_I2C_IO = 4
CMD_I2C_BEGIN = 1
CMD_I2C_END = 2
STATUS_ADDRESS_ACK = 1

RT_IN = 0xC1   # vendor | interface | IN   (same as the Linux kernel driver)
RT_OUT = 0x41  # vendor | interface | OUT
I2C_M_RD = 0x0001
LIBUSB_OPTION_NO_DEVICE_DISCOVERY = 2
TIMEOUT_MS = 2000


def _load_libusb():
    names = [ctypes.util.find_library("usb-1.0"), "libusb-1.0.so", "libusb-1.0.so.0"]
    prefix = os.environ.get("PREFIX")
    if prefix:
        names.insert(0, os.path.join(prefix, "lib", "libusb-1.0.so"))
    for name in names:
        if not name:
            continue
        try:
            return ctypes.CDLL(name)
        except OSError:
            continue
    raise AteccError("libusb-1.0 not found (Termux: pkg install libusb)")


class TinyUsbTransport(Transport):
    def __init__(self, usb_fd: int, addr7: int):
        self.addr7 = addr7
        self.lib = lib = _load_libusb()
        lib.libusb_init.argtypes = [ctypes.POINTER(ctypes.c_void_p)]
        lib.libusb_wrap_sys_device.argtypes = [
            ctypes.c_void_p, ctypes.c_ssize_t, ctypes.POINTER(ctypes.c_void_p)]
        lib.libusb_control_transfer.argtypes = [
            ctypes.c_void_p, ctypes.c_uint8, ctypes.c_uint8, ctypes.c_uint16,
            ctypes.c_uint16, ctypes.c_void_p, ctypes.c_uint16, ctypes.c_uint]
        lib.libusb_close.argtypes = [ctypes.c_void_p]

        # Must be set before libusb_init: do not enumerate, we wrap one fd.
        lib.libusb_set_option(None, LIBUSB_OPTION_NO_DEVICE_DISCOVERY)
        self.ctx = ctypes.c_void_p()
        self.handle = ctypes.c_void_p()
        if lib.libusb_init(ctypes.byref(self.ctx)) != 0:
            raise AteccError("libusb_init failed")
        if lib.libusb_wrap_sys_device(self.ctx, usb_fd, ctypes.byref(self.handle)) != 0:
            raise AteccError("cannot open USB fd %d (run through termux-usb)" % usb_fd)
        # Sanity check: the adapter must report I2C functionality.
        func = self._ctrl(RT_IN, CMD_GET_FUNC, 0, 0, 4)
        if func is None:
            raise AteccError("adapter does not answer CMD_GET_FUNC (not an i2c-tiny-usb device?)")

    # -- low level ----------------------------------------------------------
    def _ctrl(self, rtype, req, value, index, length_or_data):
        """Control transfer. int -> read that many bytes (returns bytes or None
        on short/failed transfer); bytes -> write them (returns True/False)."""
        if rtype & 0x80:
            n = length_or_data
            buf = (ctypes.c_ubyte * max(n, 1))()
            r = self.lib.libusb_control_transfer(
                self.handle, rtype, req, value, index, buf, n, TIMEOUT_MS)
            return bytes(buf[:n]) if r == n else None
        data = bytes(length_or_data)
        buf = (ctypes.c_ubyte * max(len(data), 1))(*data)
        r = self.lib.libusb_control_transfer(
            self.handle, rtype, req, value, index, buf, len(data), TIMEOUT_MS)
        return r == len(data)

    def _xfer(self, addr, read, payload, first=True, last=True):
        req = CMD_I2C_IO + (CMD_I2C_BEGIN if first else 0) + (CMD_I2C_END if last else 0)
        flags = I2C_M_RD if read else 0
        out = self._ctrl(RT_IN if read else RT_OUT, req, flags, addr, payload)
        ok = out is not None if read else out
        if ok:
            st = self._ctrl(RT_IN, CMD_GET_STATUS, 0, 0, 1)
            if st is not None and st[0] == STATUS_ADDRESS_ACK:
                return out
        raise NackError("no ACK from 0x%02X" % addr)

    def set_delay(self, microseconds: int):
        """Slow the bus (CMD_SET_DELAY). Useful if the wake pulse is too short."""
        self._ctrl(RT_OUT, CMD_SET_DELAY, microseconds, 0, b"")

    # -- Transport ----------------------------------------------------------
    def wake_pulse(self):
        try:
            self._xfer(0x00, False, b"\x00")
        except NackError:
            pass  # expected

    def write(self, data):
        self._xfer(self.addr7, False, bytes(data))

    def read(self, n):
        return self._xfer(self.addr7, True, n)

    def close(self):
        if self.handle:
            self.lib.libusb_close(self.handle)
            self.handle = ctypes.c_void_p()
        if self.ctx:
            self.lib.libusb_exit(self.ctx)
            self.ctx = ctypes.c_void_p()
