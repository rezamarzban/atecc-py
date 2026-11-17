import argparse
import os
import shlex
import sys

from . import __version__
from . import config_zone as cz
from .chips import PROFILES, ChipProfile
from .errors import AteccError
from .protocol import Chip

DEFAULT_BUS = 9
DEFAULT_SLAVE = 0xC0  # 8-bit form, same as the C tool; values < 0x80 are taken as 7-bit
DEFAULT_RETRIES = 10


def eprint(*a):
    print(*a, file=sys.stderr)


def open_out(name, binary=False):
    if name in ("-", ""):
        return sys.stdout.buffer if binary else sys.stdout, False
    return open(name, "wb" if binary else "w"), True


class Context:
    def __init__(self, opts):
        self.opts = opts
        self._chip = None

    @property
    def chip(self) -> Chip:
        if self._chip is None:
            o = self.opts
            addr7 = o.slave >> 1 if o.slave >= 0x80 else o.slave
            kind = o.transport
            if kind == "auto":
                kind = "tinyusb" if (o.usb_fd is not None or os.environ.get("I2C_USB_FD")) else "i2c-dev"
            if kind == "tinyusb":
                from .transports.tinyusb import TinyUsbTransport
                fd = o.usb_fd if o.usb_fd is not None else int(os.environ["I2C_USB_FD"])
                t = TinyUsbTransport(fd, addr7)
            elif kind == "sim":
                from .transports.sim import SimTransport
                t = SimTransport(addr7=addr7)
            else:
                from .transports.linux_i2c import LinuxI2C
                t = LinuxI2C(o.bus, addr7)
            profile = PROFILES[o.chip] if o.chip else None
            self._chip = Chip(t, retries=o.retries, profile=profile)
        return self._chip

    def close(self):
        if self._chip is not None:
            self._chip.close()


# -- commands ----------------------------------------------------------------
def cmd_serial(ctx, argv):
    print(ctx.chip.serial().hex())
    return 0


def cmd_info(ctx, argv):
    print("Found %s " % ctx.chip.profile.name)
    return 0


def cmd_random(ctx, argv):
    print(ctx.chip.random().hex())
    return 0


def cmd_read_config(ctx, argv):
    if len(argv) < 2:
        return help_for("read-config")
    f, close = open_out(argv[1], binary=True)
    f.write(ctx.chip.read_config())
    f.flush()
    if close:
        f.close()
    return 0


def cmd_dump_config(ctx, argv):
    if len(argv) not in (2, 3):
        return help_for("dump-config")
    if len(argv) == 3:
        with open(argv[2], "rb") as fh:
            cfg = fh.read()
        profile = next((p for p in PROFILES.values() if p.config_size == len(cfg) and p.ecc == (len(cfg) == 128)), None)
        if profile is None:
            eprint("config blob must be 88 or 128 bytes, got %d" % len(cfg))
            return 1
    else:
        cfg = ctx.chip.read_config()
        profile = ctx.chip.profile
    f, close = open_out(argv[1])
    f.write(cz.dump_config(cfg, profile))
    f.flush()
    if close:
        f.close()
    return 0


def _lock_cmd(label, fn):
    """Lock queries: print a readable answer AND keep the C tool's exit codes
    (0 = locked, 1 = not locked), because termux-usb hides the exit status."""
    def run(ctx, argv):
        locked = fn(ctx, argv)
        print("%s: %s" % (label, "LOCKED" if locked else "unlocked"))
        return 0 if locked else 1
    return run


cmd_config_is_locked = _lock_cmd("config zone", lambda c, a: cz.is_config_locked(c.chip.read_config()))
cmd_data_is_locked = _lock_cmd("data zone", lambda c, a: cz.is_data_locked(c.chip.read_config()))


def cmd_slot_is_locked(ctx, argv):
    if len(argv) < 2:
        return help_for("slot-is-locked")
    slot = int(argv[1])
    locked = cz.is_slot_locked(ctx.chip.read_config(), slot)
    print("slot %d: %s" % (slot, "LOCKED" if locked else "unlocked"))
    return 0 if locked else 1


def cmd_counter_read(ctx, argv):
    if len(argv) < 2:
        return help_for("counter-read")
    cid = int(argv[1])
    print("Counter %d: %d" % (cid, ctx.chip.counter_read(cid)))
    return 0


LOCK_QUERIES = {"config-is-locked", "data-is-locked", "slot-is-locked"}

COMMANDS = {
    "serial": (cmd_serial, "Print the 9-byte serial number in hex"),
    "info": (cmd_info, "Detect and print the chip model"),
    "random": (cmd_random, "Print 32 random bytes from the chip RNG"),
    "read-config": (cmd_read_config, "Usage: read-config output.bin|-"),
    "dump-config": (cmd_dump_config, "Usage: dump-config output.txt|- [config.bin]"),
    "config-is-locked": (cmd_config_is_locked, "Exit 0 if config zone is locked, 1 if not, 2 on error"),
    "data-is-locked": (cmd_data_is_locked, "Exit 0 if data zone is locked, 1 if not, 2 on error"),
    "slot-is-locked": (cmd_slot_is_locked, "Usage: slot-is-locked <slot>  (exit 0 locked, 1 not, 2 error)"),
    "counter-read": (cmd_counter_read, "Usage: counter-read <counter_id 0|1>"),
}


def help_for(name):
    eprint("%s: %s" % (name, COMMANDS[name][1]))
    return 1


def build_parser():
    p = argparse.ArgumentParser(prog="atecc", add_help=False)
    p.add_argument("-b", dest="bus", type=lambda s: int(s, 0), default=DEFAULT_BUS)
    p.add_argument("-s", dest="slave", type=lambda s: int(s, 0), default=DEFAULT_SLAVE)
    p.add_argument("-c", dest="cmds", action="append", default=[])
    p.add_argument("-r", dest="retries", type=int, default=DEFAULT_RETRIES)
    p.add_argument("-v", dest="version", action="store_true")
    p.add_argument("-h", dest="help", nargs="?", const="", default=None)
    p.add_argument("-t", "--transport", choices=["auto", "i2c-dev", "tinyusb", "sim"], default="auto")
    p.add_argument("--usb-fd", type=int, default=None, help="USB fd from termux-usb (tinyusb transport)")
    p.add_argument("--chip", choices=sorted(PROFILES), default=None, help="skip auto-detection")
    return p


def usage():
    eprint("atecc-py %s" % __version__)
    eprint('Usage: atecc [-b bus] [-s addr] [-t transport] [--usb-fd N] [-r retries] -c "cmd args" [-c ...]')
    eprint("Available commands:")
    for name, (_, h) in COMMANDS.items():
        eprint("\t%-18s %s" % (name, h))


def main(argv=None) -> int:
    opts = build_parser().parse_args(argv)
    if opts.version:
        eprint("atecc-py %s" % __version__)
        return 0
    if opts.help is not None:
        if opts.help:
            if opts.help in COMMANDS:
                help_for(opts.help)
                return 0
            eprint("Unknown command: %s" % opts.help)
            return 1
        usage()
        return 0
    if not opts.cmds:
        usage()
        return 1

    ctx = Context(opts)
    ret = 0
    try:
        for text in opts.cmds:
            try:
                words = shlex.split(text)
            except ValueError as e:
                eprint("cmd '%s': commandline parse error (%s)" % (text, e))
                return 1
            if not words or words[0] not in COMMANDS:
                eprint("Unknown command: %s" % (words[0] if words else text))
                usage()
                return 1
            ret = COMMANDS[words[0]][0](ctx, words)
            # "not locked" (1) from a lock query is an answer, not a failure:
            # keep running the remaining commands.
            if ret != 0 and not (ret == 1 and words[0] in LOCK_QUERIES):
                break
    except AteccError as e:
        eprint("error: %s" % e)
        ret = 2
    except (OSError, ValueError) as e:
        eprint("error: %s" % e)
        ret = 2
    finally:
        ctx.close()
    return ret
