"""Host-side session crypto (port of cryptoauthlib atca_host.c, the parts used here).

All functions are pure: they take the values the chip returned and compute what the
chip computed, so TempKey on the host matches TempKey inside the chip.
"""
import hashlib
from dataclasses import dataclass, field

OP_WRITE, OP_GENDIG, OP_PRIVWRITE = 0x12, 0x15, 0x46

NONCE_MODE_MASK = 0x03
NONCE_SEED_UPDATE, NONCE_NO_SEED_UPDATE, NONCE_PASSTHROUGH = 0x00, 0x01, 0x03

GENDIG_ZONE_DATA = 2


def sha256(*parts: bytes) -> bytes:
    h = hashlib.sha256()
    for p in parts:
        h.update(p)
    return h.digest()


@dataclass
class TempKey:
    value: bytes = bytes(32)
    valid: bool = False
    source_flag: int = 0
    key_id: int = 0
    gen_dig_data: int = 0
    no_mac_flag: int = 0


OP_NONCE = 0x16


def nonce_random(num_in: bytes, rand_out: bytes, mode: int = NONCE_SEED_UPDATE) -> TempKey:
    """TempKey after Nonce in random mode: SHA256(RandOut | NumIn | opcode | mode | 0x00)."""
    if len(num_in) != 20 or len(rand_out) != 32:
        raise ValueError("num_in must be 20 bytes and rand_out 32 bytes")
    msg = rand_out + num_in + bytes([OP_NONCE, mode, 0x00])
    assert len(msg) == 55
    return TempKey(value=sha256(msg), valid=True, source_flag=0)


def gen_dig_data(sn: bytes, key_slot: int, stored_key: bytes, tk: TempKey) -> TempKey:
    """TempKey after GenDig with zone=Data, as used for encrypted read/write/auth.

    `sn` is the 9-byte serial number. OtherData form (NoMac-independent) is assumed,
    exactly like cryptoauthlib's atcab_write_enc / atcab_read_enc.
    """
    other = bytes([OP_GENDIG, GENDIG_ZONE_DATA, key_slot & 0xFF, key_slot >> 8])
    msg = (stored_key + other + bytes([sn[8], sn[0], sn[1]]) + bytes(25) + tk.value)
    assert len(msg) == 96
    return TempKey(value=sha256(msg), valid=True, source_flag=tk.source_flag,
                   key_id=key_slot & 0xF, gen_dig_data=1)


def write_auth(tk: TempKey, sn: bytes, zone_param: int, addr: int, plain: bytes):
    """Encrypted 32-byte write: returns (cipher, mac)."""
    if not tk.valid or tk.no_mac_flag:
        raise ValueError("TempKey not usable for encrypted write")
    cipher = bytes(a ^ b for a, b in zip(plain, tk.value))
    mac_in = (tk.value + bytes([OP_WRITE, zone_param, addr & 0xFF, addr >> 8,
                                sn[8], sn[0], sn[1]]) + bytes(25) + plain)
    assert len(mac_in) == 96
    return cipher, sha256(mac_in)


def privwrite_auth(tk: TempKey, sn: bytes, key_id: int, plain36: bytes, mode: int = 0x40):
    """Encrypted private-key write: returns (cipher36, mac)."""
    if len(plain36) != 36:
        raise ValueError("private key payload must be 36 bytes")
    if not tk.valid or tk.no_mac_flag:
        raise ValueError("TempKey not usable for encrypted private write")
    key2 = sha256(tk.value)
    cipher = (bytes(a ^ b for a, b in zip(plain36[:32], tk.value))
              + bytes(a ^ b for a, b in zip(plain36[32:], key2[:4])))
    mac_in = (tk.value + bytes([OP_PRIVWRITE, mode, key_id & 0xFF, key_id >> 8,
                                sn[8], sn[0], sn[1]]) + bytes(21) + plain36)
    assert len(mac_in) == 96
    return cipher, sha256(mac_in)


def check_mac_response(mode: int, slot_key: bytes, challenge: bytes, other_data: bytes,
                       sn: bytes, tk: TempKey = None, otp: bytes = None) -> bytes:
    """Client response for CheckMac (13 bytes of other_data)."""
    if len(other_data) != 13:
        raise ValueError("other_data must be 13 bytes")
    block1_tk, block2_tk = mode & 0x02, mode & 0x01
    if block1_tk or block2_tk:
        if tk is None or not tk.valid:
            raise ValueError("TempKey required and must be valid")
        if ((mode >> 2) & 1) != tk.source_flag:
            raise ValueError("TempKey source flag does not match mode bit 2")
    msg = bytearray(88)
    msg[0:32] = tk.value if block1_tk else slot_key
    msg[32:64] = tk.value if block2_tk else (challenge or bytes(32))
    msg[64:68] = other_data[0:4]
    if mode & 0x20:
        msg[68:76] = otp
    msg[76:79] = other_data[4:7]
    msg[79] = sn[8]
    msg[80:84] = other_data[7:11]
    msg[84:86] = sn[0:2]
    msg[86:88] = other_data[11:13]
    return sha256(bytes(msg))
