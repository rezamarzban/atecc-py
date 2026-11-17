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


# Exact signatures from cryptoauthlib (atcab_device_type), plus ATECC608B.
SIGNATURES = {
    bytes([0x00, 0x00, 0x60, 0x01]): "ATECC608A",
    bytes([0x00, 0x00, 0x60, 0x02]): "ATECC608A",
    bytes([0x00, 0x00, 0x60, 0x03]): "ATECC608B",
    bytes([0x00, 0x00, 0x50, 0x00]): "ATECC508A",
    bytes([0x80, 0x00, 0x10, 0x01]): "ATECC108A",
    bytes([0x00, 0x02, 0x00, 0x08]): "ATSHA204A",
    bytes([0x00, 0x02, 0x00, 0x09]): "ATSHA204A",
    bytes([0x00, 0x04, 0x05, 0x00]): "ATSHA204A",
}


def detect(revision: bytes) -> ChipProfile:
    """Map the 4-byte DevRev (Info mode 0) to a profile.

    Exact matches follow CryptoAuthLib. Unknown revisions fall back to the family
    byte (rev[2]); the 608B (00 00 60 03) mapping is an addition not in that table.
    """
    if len(revision) != 4:
        raise ValueError("revision must be 4 bytes")
    name = SIGNATURES.get(bytes(revision))
    if name is None:
        fam = {0x60: "ATECC608A", 0x50: "ATECC508A", 0x10: "ATECC108A",
               0x40: "ATSHA206A", 0x00: "ATSHA204A", 0x05: "ATSHA204A"}.get(revision[2])
        if fam is None:
            raise ValueError("unknown device revision %s" % revision.hex())
        name = fam
    return PROFILES[name]
