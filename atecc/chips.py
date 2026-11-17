from dataclasses import dataclass


@dataclass(frozen=True)
class ChipProfile:
    name: str
    config_size: int      # bytes in the configuration zone
    ecc: bool             # has ECC commands / KeyConfig
    aes: bool             # has AES/KDF family (608 only)
    counters: tuple       # usable monotonic counter ids


PROFILES = {
    "ATECC608B": ChipProfile("ATECC608B", 128, True, True, (0, 1)),
    "ATECC608A": ChipProfile("ATECC608A", 128, True, True, (0, 1)),
    "ATECC508A": ChipProfile("ATECC508A", 128, True, False, (0, 1)),
    "ATECC108A": ChipProfile("ATECC108A", 128, True, False, (0, 1)),
    "ATSHA204A": ChipProfile("ATSHA204A", 88, False, False, ()),
    "ATSHA206A": ChipProfile("ATSHA206A", 88, False, False, ()),
}


def detect(revision: bytes) -> ChipProfile:
    """Map the 4-byte DevRev (Info mode 0) to a profile.

    Only the 608A revision (00 00 60 02) is checked against real hardware use;
    the other mappings follow the CryptoAuthLib convention and are best-effort.
    """
    if len(revision) != 4:
        raise ValueError("revision must be 4 bytes")
    family = revision[2]
    if family == 0x60:
        return PROFILES["ATECC608A"] if revision[3] < 0x03 else PROFILES["ATECC608B"]
    if family == 0x50:
        return PROFILES["ATECC508A"]
    if family == 0x10:
        return PROFILES["ATECC108A"]
    if family == 0x40:
        return PROFILES["ATSHA206A"]
    if family in (0x00, 0x02):
        return PROFILES["ATSHA204A"]
    raise ValueError("unknown device revision %s" % revision.hex())
