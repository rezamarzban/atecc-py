# atecc-py

Python port of [atecc-util](https://github.com/rezamarzban/atecc-util) with **no C dependency**.
Standard library only; runs on Linux and in Termux on Android.

The command logic was ported from the CryptoAuthLib source that atecc-util builds against
(wirenboard fork, commit 590807a), not from memory. The host-side session crypto (nonce, gendig,
checkmac, encrypted write/private-write MACs) is checked against the C implementation's output.

## Transports
| `-t` | What it does |
|---|---|
| `i2c-dev` | `/dev/i2c-N` (Linux, or Termux with the old LD_PRELOAD shim) |
| `tinyusb` | **Python port of `i2cshim.c`**: I2C-Tiny-USB over the fd from `termux-usb`, via libusb + ctypes |
| `sim` | In-memory chip for tests/dry runs (ECC/AES in the simulator need `cryptography`) |
| `auto` | `tinyusb` if `--usb-fd` / `I2C_USB_FD` is set, else `i2c-dev` |

## Termux
```
pkg install python libusb
ATECC_ARGS="-c info -c serial" termux-usb -r -e ~/atecc-py/scripts/atecc-termux /dev/bus/usb/002/002
```
Commands that take arguments go in single quotes inside `ATECC_ARGS`:
`ATECC_ARGS="-c info -c 'counter-read 1'"`

## Commands
Same options and exit codes as the C tool (`-b -s -c -r -v -h`; `-s` takes 0xC0 or 0x60 style).
Run `python3 -m atecc -h` for the list, `-h <command>` for usage.

| Group | Commands |
|---|---|
| Identify | `info` `serial` `random` `selftest` |
| Config | `read-config` `write-config` `dump-config` `lock-config` `config-is-locked` `extra-get` `extra-set` |
| Data zone | `write-data` `read-data` `hmac-write-key` `write-data-block` `lock-data` `data-is-locked` `lock-slot` `slot-is-locked` |
| Counters | `counter-read` (0, 1, 15) `counter-inc` `counter-init` |
| ECC | `ecc-gen` `ecc-write` `ecc-read-pub` `ecc-gen-pub` `ecc-sign` `ecc-verify` `ecdh` |
| HMAC / AES | `hmac-dgst` `aes` (ATECC608 only) |
| Auth | `auth-passwd` `auth-make-passwd` `auth-check-gendig` |

The library (`atecc.Chip`) additionally exposes `mac`, `derive_key`, `info` modes, `read_enc`/`write_enc`,
`nonce_*`, `gendig`, `checkmac`. KDF and SecureBoot are **not implemented**.

## Safety
- `lock-config`, `lock-data`, `lock-slot` are irreversible and refuse to run without `--yes-lock`.
- `write-config` refuses a locked chip, and refuses a blob that changes the I2C address byte (16)
  unless `--allow-i2c-change` is given (a wrong address makes the chip unreachable).
- Commands that must not run twice (`counter-inc`, locks, `ecc-gen`, `extra-set`) are never retried
  after the chip may have executed them.
- Back up first: `-c 'read-config backup.bin'`.

## Differences from the C tool
- Lock queries also print `... : LOCKED/unlocked` (the exit code is unchanged, and "not locked" no
  longer aborts the rest of a `-c` chain).
- `auth-passwd` / `auth-check-gendig` send a full 13-byte CheckMac OtherData; the C tool read
  past the end of a 12/4-byte array there.
- `write-config` can be given `--chip` to skip detection; the offline `dump-config out in.bin` needs no chip.

## Status
- Hardware-verified (ATECC608A via tinyusb): `info`, `serial`, lock queries.
- Everything else is verified against the simulator and the C reference vectors only. The simulator
  shares my reading of the protocol, so run read-only commands first and keep the chip unlocked
  while experimenting.
- ATECC608A is the primary target; 608B/508A/108A/ATSHA204A profiles follow CryptoAuthLib's tables.
  `hmac-dgst` and `aes` need an ATECC608.

Tests: `python3 -m unittest discover -s tests`
