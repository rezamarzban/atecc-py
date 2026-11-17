# atecc-py

Python port of [atecc-util](https://github.com/rezamarzban/atecc-util) with no C dependency.
Pure standard library; runs on Linux and in Termux on Android.

## Transports
| `-t` | What it does |
|---|---|
| `i2c-dev` | `/dev/i2c-N` (Linux, or Termux with the old LD_PRELOAD shim) |
| `tinyusb` | **Python port of `i2cshim.c`**: I2C-Tiny-USB over the fd from `termux-usb`, via libusb + ctypes |
| `sim` | In-memory chip for tests (read-only, synthetic config) |
| `auto` | `tinyusb` if `--usb-fd`/`I2C_USB_FD` is set, else `i2c-dev` |

## Termux
```
pkg install python libusb
ATECC_ARGS="-c info -c serial" termux-usb -r -e ~/atecc-py/scripts/atecc-termux /dev/bus/usb/002/002
```
If the chip does not wake, the adapter bus may be too fast for the wake pulse:
`TinyUsbTransport.set_delay(us)` exposes `CMD_SET_DELAY`.

## Commands (phase 1, read-only)
`serial info random read-config dump-config config-is-locked data-is-locked slot-is-locked counter-read`

Same `-b -s -c -r -v -h` options and exit codes as the C tool. `-s` accepts the 8-bit form (0xC0) or 7-bit (0x60).

## Status
- Verified: CRC-16 and the DevRev frame against known vectors; protocol/CLI against the simulator (`python -m unittest discover -s tests`).
- **Not yet verified on hardware.** ATECC608A is the first target; the 608B/508A/108A/SHA204A profiles are best-effort.
- Write/lock/ECC/HMAC/AES commands are intentionally not in this phase.
