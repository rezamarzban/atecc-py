"""Human-readable decoding of the configuration zone (port of atecc_config_zone.c)."""
from .chips import ChipProfile

SLOT_CONFIG_OFFSET = 20
KEY_CONFIG_OFFSET = 96
LOCK_VALUE_OFFSET = 86     # data zone lock: 0x55 unlocked, anything else locked
LOCK_CONFIG_OFFSET = 87    # config zone lock
SLOT_LOCKED_OFFSET = 88    # 16 bits, bit set = slot UNLOCKED (ECC parts only)

KEY_TYPES = {4: "P256", 6: "AES", 7: "SHA or other"}


def _b(v, n):
    return (v >> n) & 1


def decode_slot_config(value: int, ecc: bool = True) -> list:
    out = ["Decoding SlotConfig value = 0x%04X" % value]
    out.append("Read key (except ECC private keys): %d" % (value & 0xF))
    if ecc:
        out += [
            " If slot contains ECC private keys:",
            "  External signatures of arbitrary messages are enabled: %d" % _b(value, 0),
            "  Internal signatures are enabled: %d" % _b(value, 1),
            "  ECDH operation is permitted for this key: %d" % _b(value, 2),
            "   ECDH master secret output mode: %d" % _b(value, 3),
            "NoMac bit: %d" % _b(value, 4),
            "LimitedUse bit: %d" % _b(value, 5),
        ]
    else:
        out += ["CheckOnly bit: %d" % _b(value, 4), "SingleUse bit: %d" % _b(value, 5)]
    out += [
        "EncryptRead bit: %d" % _b(value, 6),
        "IsSecret bit: %d" % _b(value, 7),
        "Write key: %d" % ((value >> 8) & 0xF),
    ]
    wc = (value >> 12) & 0xF
    out.append("Write config: 0x%X (hex) = %s (bin)" % (wc, format(wc, "04b")))

    if wc == 0b0000:
        w = "Always"
    elif wc == 0b0001:
        w = "PubInvalid"
    elif (wc & 0b1110) == 0b0010 or (wc & 0b1100) == 0b1000:
        w = "Never"
    elif wc & 0b0100:
        w = "Encrypt"
    else:
        w = "Unknown"
    out.append("  Write cmd: " + w)

    m = wc & 0b1011
    if m == 0b0010:
        d = "Roll without MAC"
    elif m == 0b1010:
        d = "Roll with MAC"
    elif m == 0b0011:
        d = "Create without MAC"
    elif m == 0b1011:
        d = "Create with MAC"
    elif (wc & 0b0010) == 0:
        d = "Can't be used"
    else:
        d = "Unknown"
    out.append("  DeriveKey cmd: " + d)
    if ecc:
        out.append("  GenKey cmd: %s " % ("may be used" if wc & 2 else "may NOT be used"))
        out.append("  PrivWrite cmd: %s " % ("Encrypt" if wc & 4 else "Forbidden"))
    return out


def decode_key_config(value: int) -> list:
    kt = (value >> 2) & 0b111
    return [
        "Decoding KeyConfig value = 0x%04X" % value,
        "Private bit: %d" % _b(value, 0),
        "PubInfo bit: %d" % _b(value, 1),
        "KeyType: %d [%s]" % (kt, KEY_TYPES.get(kt, "unknown")),
        "Lockable bit: %d" % _b(value, 5),
        "ReqRandom bit: %d" % _b(value, 6),
        "ReqAuth bit: %d" % _b(value, 7),
        "AuthKey: %d" % ((value >> 8) & 0xF),
        "IntrusionDisable bit: %d" % _b(value, 12),
        "X509id: %d" % ((value >> 14) & 0b11),
    ]


def is_config_locked(cfg: bytes) -> bool:
    return cfg[LOCK_CONFIG_OFFSET] != 0x55


def is_data_locked(cfg: bytes) -> bool:
    return cfg[LOCK_VALUE_OFFSET] != 0x55


def is_slot_locked(cfg: bytes, slot: int) -> bool:
    mask = cfg[SLOT_LOCKED_OFFSET] | (cfg[SLOT_LOCKED_OFFSET + 1] << 8)
    return not (mask >> slot) & 1


def dump_config(cfg: bytes, profile: ChipProfile) -> str:
    L = ["============= Config zone dump: ============= "]
    for i, byte in enumerate(cfg):
        if i % 4 == 0:
            L.append("")
        L[-1] += "%03d: %02X\t\t" % (i, byte)
    L.append("")
    if profile.ecc:
        L.append("===== Individual locks configuration ==")
        for slot in range(16):
            L.append(" Slot %02d: %s" % (slot, "LOCKED" if is_slot_locked(cfg, slot) else "unlocked"))
        L.append("")
    L.append("===== Slot configurations============")
    for slot in range(16):
        o = SLOT_CONFIG_OFFSET + slot * 2
        L.append("=========================  Slot: %d   ================== " % slot)
        L += decode_slot_config(cfg[o] | (cfg[o + 1] << 8), profile.ecc)
        if profile.ecc:
            k = KEY_CONFIG_OFFSET + slot * 2
            L.append("-------------")
            L += decode_key_config(cfg[k] | (cfg[k + 1] << 8))
    return "\n".join(L) + "\n"
