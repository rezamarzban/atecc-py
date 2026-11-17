"""CRC-16 used by the CryptoAuth command protocol (poly 0x8005, LSB-first bits)."""


def crc16(data: bytes) -> int:
    crc = 0
    for b in data:
        for shift in range(8):
            data_bit = (b >> shift) & 1
            crc_bit = (crc >> 15) & 1
            crc = (crc << 1) & 0xFFFF
            if data_bit != crc_bit:
                crc ^= 0x8005
    return crc


def crc16_le(data: bytes) -> bytes:
    return crc16(data).to_bytes(2, "little")
