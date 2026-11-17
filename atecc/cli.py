import argparse
import hashlib
import os
import shlex
import sys

from . import __version__
from . import config_zone as cz
from .chips import PROFILES
from .errors import AteccError, ChipStatusError
from .protocol import (COUNTER_MAX_VALUE, UPDATE_SELECTOR, UPDATE_USER_EXTRA, ZONE_CONFIG,
                       ZONE_DATA, Chip)

DEFAULT_BUS = 9
DEFAULT_SLAVE = 0xC0  # 8-bit form, same as the C tool; values < 0x80 are taken as 7-bit
DEFAULT_RETRIES = 10
MAX_PASSWD_LEN = 256
PASSWD_SALT = b"atecc-salt123"
COUNTER15_SIZE = 16
COUNTER15_MAX_VALUE = COUNTER15_SIZE * 8
COUNTER15_OFFSET = 68


class Usage(Exception):
    """Wrong arguments: print the command's help, exit status 1."""


def eprint(*a):
    print(*a, file=sys.stderr)


def read_file(name: str, limit: int = None) -> bytes:
    if name == "-":
        data = sys.stdin.buffer.read()
    else:
        with open(name, "rb") as f:
            data = f.read()
    return data if limit is None else data[:limit]


def read_exact(name: str, n: int, what: str) -> bytes:
    data = read_file(name, n)
    if len(data) != n:
        raise AteccError("%s: need %d bytes, got %d" % (what, n, len(data)))
    return data


def write_file(name: str, data: bytes):
    if name == "-":
        buf = getattr(sys.stdout, "buffer", None)
        if buf is None:  # redirected to a text stream (tests, embedding)
            sys.stdout.write(data.decode("utf-8", "replace"))
        else:
            buf.write(data)
            buf.flush()
    else:
        with open(name, "wb") as f:
            f.write(data)


def read_passwd(name: str) -> bytes:
    line = read_file(name).split(b"\n", 1)[0]
    return line[:MAX_PASSWD_LEN]


def key_from_password(pw: bytes) -> bytes:
    return hashlib.sha256(pw + PASSWD_SALT).digest()


def sha256_file(name: str) -> bytes:
    h = hashlib.sha256()
    if name == "-":
        src = sys.stdin.buffer
        for chunk in iter(lambda: src.read(65536), b""):
            h.update(chunk)
    else:
        with open(name, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
    return h.digest()


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
                from .transports import sim
                t = sim.SHARED if sim.SHARED is not None else sim.SimTransport(addr7=addr7)
            else:
                from .transports.linux_i2c import LinuxI2C
                t = LinuxI2C(o.bus, addr7)
            profile = PROFILES[o.chip] if o.chip else None
            self._chip = Chip(t, retries=o.retries, profile=profile)
        return self._chip

    def require_irreversible(self, what):
        if not self.opts.yes_lock:
            eprint("Refusing to %s: this cannot be undone. Re-run with --yes-lock to confirm." % what)
            return False
        return True

    def close(self):
        if self._chip is not None:
            self._chip.close()


def argn(argv, minimum, maximum=None):
    n = len(argv)
    if n < minimum or (maximum is not None and n > maximum):
        raise Usage()


def to_int(s):
    return int(s, 0)


def check_slot(n):
    if not 0 <= n <= 15:
        raise AteccError("slot must be 0-15")
    return n


# ---------------------------------------------------------------- identification
def cmd_serial(ctx, argv):
    print(ctx.chip.serial().hex())
    return 0


def cmd_info(ctx, argv):
    print("Found %s " % ctx.chip.profile.name)
    return 0


def cmd_random(ctx, argv):
    print(ctx.chip.random().hex())
    return 0


def cmd_selftest(ctx, argv):
    ctx.chip.selftest()
    print("Self-test passed")
    return 0


# ---------------------------------------------------------------- configuration
def cmd_read_config(ctx, argv):
    argn(argv, 2)
    write_file(argv[1], ctx.chip.read_config())
    return 0


def cmd_dump_config(ctx, argv):
    argn(argv, 2, 3)
    if len(argv) == 3:
        cfg = read_file(argv[2])
        profile = next((p for p in PROFILES.values() if p.config_size == len(cfg)
                        and p.ecc == (len(cfg) == 128)), None)
        if profile is None:
            raise AteccError("config blob must be 88 or 128 bytes, got %d" % len(cfg))
    else:
        cfg, profile = ctx.chip.read_config(), ctx.chip.profile
    write_file(argv[1], cz.dump_config(cfg, profile).encode())
    return 0


def cmd_write_config(ctx, argv):
    argn(argv, 2)
    chip = ctx.chip
    cfg = read_file(argv[1])
    if len(cfg) != chip.profile.config_size:
        raise AteccError("config blob must be %d bytes for %s, got %d"
                         % (chip.profile.config_size, chip.profile.name, len(cfg)))
    if chip.is_locked("config"):
        raise AteccError("config zone is locked, cannot write")
    current = chip.read_config()
    if cfg[16] != current[16] and not ctx.opts.allow_i2c_change:
        raise AteccError(
            "blob changes the I2C address byte (0x%02X -> 0x%02X); the chip would stop "
            "answering at the current address. Use --allow-i2c-change if intended."
            % (current[16], cfg[16]))
    chip.write_config(cfg)
    for cid in (0, 1):
        if cid in chip.profile.counters:
            chip.write_config_counter(cid, 0)
    return 0


def cmd_lock_config(ctx, argv):
    if not ctx.require_irreversible("lock the config zone"):
        return 1
    ctx.chip.lock_config()
    return 0


def cmd_lock_data(ctx, argv):
    if not ctx.require_irreversible("lock the data zone"):
        return 1
    ctx.chip.lock_data()
    return 0


def cmd_lock_slot(ctx, argv):
    argn(argv, 2)
    if not ctx.require_irreversible("lock a slot"):
        return 1
    ctx.chip.lock_slot(check_slot(to_int(argv[1])))
    return 0


def _report_lock(label, locked):
    eprint("%s is %s" % (label, "locked" if locked else "unlocked"))
    print("%s: %s" % (label, "LOCKED" if locked else "unlocked"))
    return 0 if locked else 1


def cmd_config_is_locked(ctx, argv):
    return _report_lock("config zone", ctx.chip.is_locked("config"))


def cmd_data_is_locked(ctx, argv):
    return _report_lock("data zone", ctx.chip.is_locked("data"))


def cmd_slot_is_locked(ctx, argv):
    argn(argv, 2)
    slot = check_slot(to_int(argv[1]))
    return _report_lock("slot %d" % slot, ctx.chip.is_slot_locked(slot))


def cmd_extra_set(ctx, argv):
    argn(argv, 3)
    addr, value = to_int(argv[1]), to_int(argv[2]) & 0xFF
    if addr not in (84, 85):
        raise Usage()
    ctx.chip.update_extra(UPDATE_USER_EXTRA if addr == 84 else UPDATE_SELECTOR, value)
    return 0


def cmd_extra_get(ctx, argv):
    argn(argv, 2)
    addr = to_int(argv[1])
    if addr not in (84, 85):
        raise Usage()
    value = ctx.chip.read_bytes(ZONE_CONFIG, 0, addr - addr % 4, 4)[addr % 4]
    print("Extra %02d: 0x%02x" % (addr, value))
    return 0


# ---------------------------------------------------------------- counters
def cmd_counter_read(ctx, argv):
    argn(argv, 2, 3)
    cid = to_int(argv[1])
    rev = len(argv) == 3 and argv[2].startswith("-r")
    if cid in (0, 1):
        value = ctx.chip.counter_read(cid)
        if rev:
            value = COUNTER_MAX_VALUE - value
    elif cid == 15:
        buf = ctx.chip.read_bytes(ZONE_CONFIG, 0, COUNTER15_OFFSET, COUNTER15_SIZE)
        value = sum(bin(b).count("1") for b in buf)
        if not rev:
            value = COUNTER15_MAX_VALUE - value
    else:
        eprint("Unknown counter: %d" % cid)
        raise Usage()
    print("Counter %d: %d" % (cid, value))
    return 0


def cmd_counter_inc(ctx, argv):
    argn(argv, 2)
    cid = to_int(argv[1])
    if cid not in (0, 1):
        raise Usage()
    print("Counter %d: %d" % (cid, ctx.chip.counter_increment(cid)))
    return 0


def counter15_fill(value: int) -> bytes:
    buf = bytearray(COUNTER15_SIZE)
    for i in range(COUNTER15_SIZE):
        for _ in range(8):
            if value <= 0:
                break
            buf[i] = (buf[i] >> 1) | 0x80
            value -= 1
    return bytes(buf)


def cmd_counter_init(ctx, argv):
    argn(argv, 3)
    cid, value = to_int(argv[1]), to_int(argv[2])
    rev = value < 0
    value = abs(value)
    if cid in (0, 1):
        if rev:
            value = COUNTER_MAX_VALUE - value
        ctx.chip.write_config_counter(cid, value)
    elif cid == 15:
        if value > COUNTER15_MAX_VALUE:
            raise AteccError("Value is too high: %d > %d" % (value, COUNTER15_MAX_VALUE))
        if not rev:
            value = COUNTER15_MAX_VALUE - value
        ctx.chip.write_bytes(ZONE_CONFIG, 0, COUNTER15_OFFSET, counter15_fill(value))
    else:
        raise Usage()
    return 0


# ---------------------------------------------------------------- data zone
def cmd_write_data(ctx, argv):
    argn(argv, 4)
    slot, offset = check_slot(to_int(argv[1])), to_int(argv[2])
    ctx.chip.write_bytes(ZONE_DATA, slot, offset, read_file(argv[3]))
    return 0


def cmd_read_data(ctx, argv):
    argn(argv, 5, 7)
    if len(argv) == 6:
        raise Usage()
    slot, offset, size = check_slot(to_int(argv[1])), to_int(argv[2]), to_int(argv[3])
    if len(argv) == 7:
        key = read_exact(argv[5], 32, "read key")
        out = ctx.chip.read_enc(slot, offset, key, to_int(argv[6]))[:min(size, 32)]
    else:
        out = ctx.chip.read_bytes(ZONE_DATA, slot, offset, size)
    write_file(argv[4], out)
    return 0


def cmd_hmac_write_key(ctx, argv):
    """hmac-write-key / write-data-block <slot> <block> <data_file> [write_key_file write_key_id]"""
    if len(argv) < 4 or len(argv) == 5 or len(argv) > 6:
        raise Usage()
    slot, block = check_slot(to_int(argv[1])), to_int(argv[2])
    data = read_exact(argv[3], 32, "data block")
    if len(argv) == 6:
        wkey = read_exact(argv[4], 32, "write key")
        ctx.chip.write_enc(slot, block, data, wkey, to_int(argv[5]))
    else:
        ctx.chip.write_zone(ZONE_DATA, slot, block, 0, data)
    return 0


def cmd_hmac_dgst(ctx, argv):
    argn(argv, 4)
    slot = check_slot(to_int(argv[1]))
    write_file(argv[3], ctx.chip.hmac(slot, read_file(argv[2])))
    return 0


# ---------------------------------------------------------------- ECC
def cmd_ecc_gen(ctx, argv):
    argn(argv, 2, 3)
    pub = ctx.chip.genkey(check_slot(to_int(argv[1])))
    if len(argv) == 3:
        write_file(argv[2], pub)
    return 0


def cmd_ecc_write(ctx, argv):
    if len(argv) not in (3, 5):
        raise Usage()
    slot = check_slot(to_int(argv[1]))
    priv = read_exact(argv[2], 32, "private key")
    if len(argv) == 5:
        ctx.chip.priv_write(slot, priv, read_exact(argv[4], 32, "write key"), to_int(argv[3]))
    else:
        ctx.chip.priv_write(slot, priv)
    return 0


def cmd_ecc_read_pub(ctx, argv):
    argn(argv, 3)
    write_file(argv[2], ctx.chip.read_pubkey(to_int(argv[1])))
    return 0


def cmd_ecc_gen_pub(ctx, argv):
    argn(argv, 3)
    write_file(argv[2], ctx.chip.get_pubkey(check_slot(to_int(argv[1]))))
    return 0


def cmd_ecc_sign(ctx, argv):
    argn(argv, 4)
    slot = check_slot(to_int(argv[1]))
    write_file(argv[3], ctx.chip.sign(slot, sha256_file(argv[2])))
    return 0


def cmd_ecc_verify(ctx, argv):
    argn(argv, 4, 5)
    slot = check_slot(to_int(argv[1]))
    digest = sha256_file(argv[2])
    sig = read_exact(argv[3], 64, "signature")
    if len(argv) == 5:
        ok = ctx.chip.verify_extern(digest, sig, read_exact(argv[4], 64, "public key"))
    else:
        ok = ctx.chip.verify_stored(digest, sig, slot)
    eprint("Verification OK" if ok else "Verification FAILED")
    return 0 if ok else 1


def cmd_ecdh(ctx, argv):
    argn(argv, 3, 4)
    slot = check_slot(to_int(argv[1]))
    secret = ctx.chip.ecdh(slot, read_exact(argv[2], 64, "public key"))
    if len(argv) == 4:
        write_file(argv[3], secret)
    return 0


# ---------------------------------------------------------------- AES (608)
def cmd_aes(ctx, argv):
    """aes <encrypt|decrypt> <key_slot> <key_block 0-3> <in16|-> <out|->"""
    argn(argv, 6)
    if argv[1] not in ("encrypt", "decrypt"):
        raise Usage()
    block = to_int(argv[3])
    if not 0 <= block <= 3:
        raise Usage()
    mode = (block << 6) | (1 if argv[1] == "decrypt" else 0)
    write_file(argv[5], ctx.chip.aes(mode, check_slot(to_int(argv[2])),
                                     read_exact(argv[4], 16, "AES block")))
    return 0


# ---------------------------------------------------------------- authentication
def cmd_auth_passwd(ctx, argv):
    argn(argv, 3)
    ok = ctx.chip.auth_password(check_slot(to_int(argv[1])),
                                key_from_password(read_passwd(argv[2])))
    if not ok:
        eprint("Authentication failure")
    return 0 if ok else 1


def cmd_auth_make_passwd(ctx, argv):
    argn(argv, 3)
    ctx.chip.write_bytes(ZONE_DATA, check_slot(to_int(argv[1])), 0,
                         key_from_password(read_passwd(argv[2])))
    return 0


def cmd_auth_check_gendig(ctx, argv):
    argn(argv, 3)
    ok = ctx.chip.auth_check_gendig(check_slot(to_int(argv[1])),
                                    read_exact(argv[2], 32, "key file"))
    eprint("Keys match" if ok else "Keys doesn't match")
    return 0 if ok else 1


LOCK_QUERIES = {"config-is-locked", "data-is-locked", "slot-is-locked"}

COMMANDS = {
    "serial": (cmd_serial, "Print the 9-byte serial number in hex"),
    "info": (cmd_info, "Detect and print the chip model"),
    "random": (cmd_random, "Print 32 random bytes from the chip RNG"),
    "selftest": (cmd_selftest, "Run the chip self-test"),
    "write-config": (cmd_write_config, "Usage: write-config input.bin|-"),
    "read-config": (cmd_read_config, "Usage: read-config output.bin|-"),
    "dump-config": (cmd_dump_config, "Usage: dump-config output.txt|- [config.bin]"),
    "lock-config": (cmd_lock_config, "Lock the config zone. CAN'T BE UNDONE (needs --yes-lock)"),
    "config-is-locked": (cmd_config_is_locked, "Exit 0 if locked, 1 if not, 2 on error"),
    "hmac-write-key": (cmd_hmac_write_key,
                       "Usage: hmac-write-key <slot> <block_offset> data_file [write_key_file write_key_id]"),
    "hmac-dgst": (cmd_hmac_dgst, "Usage: hmac-dgst <slot> payload|- hmac_output|-   (ATECC608)"),
    "ecc-gen": (cmd_ecc_gen, "Usage: ecc-gen <slot> [pubkey_file]"),
    "ecc-write": (cmd_ecc_write,
                  "Usage: ecc-write <slot> private_key_file [<write_key_slot> write_key_file]"),
    "ecc-read-pub": (cmd_ecc_read_pub, "Usage: ecc-read-pub <slot 8-15> pubkey_file"),
    "ecc-gen-pub": (cmd_ecc_gen_pub, "Usage: ecc-gen-pub <slot> pubkey_file"),
    "ecc-sign": (cmd_ecc_sign, "Usage: ecc-sign <slot> message_file signature_file"),
    "ecc-verify": (cmd_ecc_verify, "Usage: ecc-verify <slot> message_file signature_file [pubkey]"),
    "ecdh": (cmd_ecdh, "Usage: ecdh <slot> public_key [secret_file]"),
    "write-data": (cmd_write_data, "Usage: write-data <slot> <offset> input_file  (plaintext)"),
    "write-data-block": (cmd_hmac_write_key,
                         "Usage: write-data-block <slot> <block_offset> data_file [write_key_file write_key_id]"),
    "read-data": (cmd_read_data,
                  "Usage: read-data <slot> <offset> <size> output_file [readkey_file <readkey_slot>]"),
    "lock-data": (cmd_lock_data, "Lock the data zone. CAN'T BE UNDONE (needs --yes-lock)"),
    "data-is-locked": (cmd_data_is_locked, "Exit 0 if locked, 1 if not, 2 on error"),
    "lock-slot": (cmd_lock_slot, "Usage: lock-slot <slot>. CAN'T BE UNDONE (needs --yes-lock)"),
    "slot-is-locked": (cmd_slot_is_locked, "Usage: slot-is-locked <slot>  (0 locked, 1 not, 2 error)"),
    "counter-read": (cmd_counter_read, "Usage: counter-read <id 0|1|15> [-r]"),
    "counter-inc": (cmd_counter_inc, "Usage: counter-inc <id 0|1>"),
    "counter-init": (cmd_counter_init, "Usage: counter-init <id 0|1|15> <value>  (negative = counts left)"),
    "extra-set": (cmd_extra_set, "Usage: extra-set <84|85> <value>  (one-time write)"),
    "extra-get": (cmd_extra_get, "Usage: extra-get <84|85>"),
    "aes": (cmd_aes, "Usage: aes <encrypt|decrypt> <key_slot> <key_block 0-3> <in16|-> <out|->  (ATECC608)"),
    "auth-passwd": (cmd_auth_passwd, "Usage: auth-passwd <slot> password_file"),
    "auth-make-passwd": (cmd_auth_make_passwd, "Usage: auth-make-passwd <slot> password_file"),
    "auth-check-gendig": (cmd_auth_check_gendig, "Usage: auth-check-gendig <slot> key_file"),
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
    p.add_argument("--yes-lock", action="store_true",
                   help="confirm irreversible operations (lock-config, lock-data, lock-slot)")
    p.add_argument("--allow-i2c-change", action="store_true",
                   help="let write-config change the chip's I2C address byte")
    return p


def usage():
    eprint("atecc-py %s" % __version__)
    eprint('Usage: atecc [-b bus] [-s addr] [-t transport] [--usb-fd N] [-r retries] '
           '[--yes-lock] -c "cmd args" [-c ...]')
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
            try:
                ret = COMMANDS[words[0]][0](ctx, words)
            except Usage:
                ret = help_for(words[0])
            # "not locked" (1) from a lock query is an answer, not a failure.
            if ret != 0 and not (ret == 1 and words[0] in LOCK_QUERIES):
                break
    except ChipStatusError as e:
        eprint("error: %s" % e)
        ret = 2
    except AteccError as e:
        eprint("error: %s" % e)
        ret = 2
    except (OSError, ValueError) as e:
        eprint("error: %s" % e)
        ret = 2
    finally:
        ctx.close()
    return ret
