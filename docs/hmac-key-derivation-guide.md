# ATECC608A: HMAC key derivation, slot testing and verification (Termux)

This guide shows how to use atecc-py on Android/Termux to write HMAC keys into
ATECC608A slots, verify that a key was written correctly, derive encryption
keys on the chip, and test slots 0-15 with HMAC and ECC. The commands and
scripts were tested on one ATECC608A (revision `0x00006002`) with the config
zone locked and the data zone unlocked. Behavior may differ on other chips or
after the data zone is locked; see [Observations](#3-observations-on-the-tested-chip).

> **Warning.** `lock-data`, `lock-config` and `lock-slot` cannot be undone.
> Several scripts below overwrite slot contents. Read each section before running it.

---

## 1. Setup

Define a helper once per Termux session. All later commands use it:

```bash
at() { ATECC_ARGS="-c '$*'" termux-usb -r -e ~/atecc-py/scripts/atecc-termux /dev/bus/usb/002/002; }
```

Change `/dev/bus/usb/002/002` to your device path (`termux-usb -l`).

Basic commands:

```bash
at info                  # detect chip model
at selftest              # run chip self-test
at serial                # 9-byte serial number
at data-is-locked        # data zone lock state
at config-is-locked      # config zone lock state
at slot-is-locked 10     # per-slot lock state
at dump-config -         # decode full config zone
```

Syntax notes:

- Write `~` plainly. `\~` is not expanded by the shell and gives "No such file".
- Empty output from `at` usually means success (no error was printed).
- `termux-usb` appends an empty line to the output. `tail -1` returns that empty
  line, so use `grep` to pick the line you want.

---

## 2. Reading the config of the tested chip

| Item | Value | Meaning |
|---|---|---|
| Model | ATECC608A | self-test passed |
| Byte 87 (LockConfig) | `00` | config zone **locked** |
| Byte 86 (LockValue) | `55` | data zone **unlocked** |
| Byte 13 (AES_Enable) | `C1` | AES enable bit is set |

Slot layout of the tested config:

| Slot | SlotConfig | KeyConfig | Type | IsSecret | Notes |
|---|---|---|---|---|---|
| 0-9 | `0x2081` | `0x0013` | P256 private key | 1 | external signatures allowed, ECDH disabled, GenKey allowed, PrivWrite forbidden |
| 10 | `0x8F8F` | `0x0018` | AES | 1 | WriteConfig = 8 (decoded as "Never") |
| 11 | `0x8F8F` | `0x001C` | SHA / HMAC | 1 | secret HMAC key slot |
| 12 | `0x0000` | `0x0030` | P256, lockable | 0 | not secret, write "Always" |
| 13, 14 | `0x0000` | `0x003C` | SHA, lockable | 0 | not secret, write "Always" |
| 15 | `0x8F8F` | `0x001C` | SHA / HMAC | 1 | same as slot 11 |

---

## 3. Observations on the tested chip

### 3.1 Reading slots
- `read-data` on slot 10 returns status `0x0F`. Slots 10, 11 and 15 have
  `IsSecret=1`, so reading their contents is always forbidden. This is expected.
- `read-data` on the non-secret slots 12-14 also returned `0x0F` while the data
  zone was unlocked. Hypothesis (unconfirmed): data-zone reads are closed until
  the data zone is locked.
- The way to verify a key is therefore to compare HMAC output with a software
  computation (section 5).

### 3.2 The `aes` command
- `aes encrypt 10 0 plain.bin cipher.bin` returned `0x03` (parse error).
- The command packet is built correctly by atecc-py (opcode `0x51`, mode 0 for
  encrypt, 16-byte input), and the same error appears on slot 11, so the
  problem is the AES command on this chip, not slot 10.
- The hypothesis "the data zone must be locked first" was **rejected**, because
  HMAC on slot 11 worked while the data zone was unlocked.
- The cause is unknown. Try again after `lock-data`.
- AES on the chip is not required: the HMAC method in section 4 gives the same
  benefit (see below).

### 3.3 Behavior before the data zone is locked
Before the data zone is locked the chip appears to be in a personalization
state and does not fully enforce slot config (hypothesis):

- HMAC worked on the AES-type slot 10 and on the non-secret slots 12-14.
- Plain-text writes worked on every slot.
- `ecc-sign` worked on slots 0-9.

**Prediction after `lock-data`** (based on the config, unconfirmed):

- Slots 11 and 15 should keep working.
- Slot 10 (AES type) and slots 12-14 may stop producing HMAC, and the contents
  of 12-14 may become readable.
- Keys in slots 10, 11 and 15 can no longer be rewritten.

### 3.4 Transient errors
- `hmac-dgst` or `write-data` sometimes returns `0x0F` once and succeeds on the
  next run, especially after a series of errors. The scripts below retry.

---

## 4. Encrypting text with HMAC key derivation

The chip never reveals the key. For each salt it derives a 256-bit key
(HMAC-SHA256), and openssl does the actual encryption on the phone.

### Step by step (slot 11)

**1. Create a 32-byte key and write it into the slot:**
```bash
openssl rand 32 > my_key.bin
at hmac-write-key 11 0 my_key.bin
```

**2. Create a salt and get the derived key from the chip:**
```bash
openssl rand 16 > salt.bin
at hmac-dgst 11 salt.bin chip_out.bin
```

**3. Compute the same value in software from the key file:**
```bash
openssl dgst -sha256 -mac HMAC -macopt hexkey:$(xxd -p -c 64 my_key.bin) -binary salt.bin > sw_out.bin
```

**4. Compare (this verifies that the key was written correctly):**
```bash
cmp chip_out.bin sw_out.bin && echo "MATCH: key is correct"
```

**5. Encrypt text:**
```bash
echo "hello world" > plain.txt
openssl rand -hex 16 > iv.hex
openssl enc -aes-256-cbc -K $(xxd -p -c 64 chip_out.bin) -iv $(cat iv.hex) -in plain.txt -out cipher.bin
xxd cipher.bin
```

**6. Decrypt with a key re-derived from the chip:**
```bash
at hmac-dgst 11 salt.bin chip_out2.bin
openssl enc -d -aes-256-cbc -K $(xxd -p -c 64 chip_out2.bin) -iv $(cat iv.hex) -in cipher.bin -out decrypted.txt
cat decrypted.txt
```

**7. Delete the raw key and derived keys (optional):**
```bash
rm my_key.bin sw_out.bin chip_out.bin chip_out2.bin
```
If you delete the raw key and lose the chip, encrypted data is gone for good.

Keep `cipher.bin`, `iv.hex` and `salt.bin` (and the chip) to decrypt later.

### Notes
- Every message uses its own salt and therefore its own key. Salt and IV are not secret.
- CBC gives confidentiality only. Add a separate HMAC (ideally with another
  slot, e.g. 15) over the ciphertext to detect tampering.
- Delete derived key files after use, otherwise the key stays on the phone.
- Deriving from a slot that has no written key is not secure (the derived key
  comes from the slot's default content). Write a key first.

### Chip-side AES (did not work on the tested chip)
```bash
printf '\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xAA\xBB\xCC\xDD\xEE\xFF' > plain.bin
at aes encrypt 10 0 plain.bin cipher.bin     # status 0x03 on the tested chip
```

---

## 5. Verifying that a key was written correctly

### `verify_key.sh`

```bash
cat > verify_key.sh << 'EOF'
#!/data/data/com.termux/files/usr/bin/bash
# usage: ./verify_key.sh <slot> <key_file>
D=/dev/bus/usb/002/002
[ $# -eq 2 ] || { echo "usage: $0 <slot> <key_file>"; exit 2; }
S=$1; K=$2
[ -f "$K" ] || { echo "key file $K not found"; exit 2; }
SZ=$(stat -c %s "$K")
[ "$SZ" -eq 32 ] || echo "WARN: key file is $SZ bytes (expected 32)"
at() { ATECC_ARGS="-c '$*'" termux-usb -r -e ~/atecc-py/scripts/atecc-termux $D 2>&1; }

ok=0; bad=0
for i in 1 2 3 4 5; do
  case $i in
    1) : > vk_salt.bin ;;
    2) printf 'a' > vk_salt.bin ;;
    *) head -c $((16*i)) /dev/urandom > vk_salt.bin ;;
  esac
  got=""
  for t in 1 2 3; do
    rm -f vk_out.bin; at hmac-dgst $S vk_salt.bin vk_out.bin >/dev/null
    [ -s vk_out.bin ] && { got=1; break; }; sleep 1
  done
  [ -n "$got" ] || { echo "test $i: chip gave no output"; bad=$((bad+1)); continue; }
  openssl dgst -sha256 -mac HMAC -macopt hexkey:$(xxd -p -c 64 "$K") -binary vk_salt.bin > vk_sw.bin
  if cmp -s vk_out.bin vk_sw.bin; then ok=$((ok+1)); else bad=$((bad+1)); echo "test $i: MISMATCH"; fi
done
rm -f vk_salt.bin vk_out.bin vk_sw.bin
if [ $bad -eq 0 ]; then echo "slot $S: VERIFIED ($ok/5 match)"; exit 0
else echo "slot $S: NOT VERIFIED ($ok ok, $bad failed)"; exit 1; fi
EOF
chmod +x verify_key.sh
```

Usage:
```bash
./verify_key.sh 11 hmac_key.bin
./verify_key.sh 15 k15.key
```

- `VERIFIED (5/5 match)`: the slot holds exactly this key.
- `MISMATCH`: the chip holds a different key (partial write or wrong file).
- `chip gave no output`: run again; if it persists, check the lock state.

Run it **after writing the key and before `lock-data`**, and again after locking.

---

## 6. HMAC test on slots 10-15: `test_hmac.sh`

Needs key files `k10.key`, `hmac_key.bin` (slot 11), `d_12.bin`, `d_13.bin`,
`d_14.bin`, `k15.key`. Adjust the `KEY` map to your own file names.

```bash
cat > test_hmac.sh << 'EOF'
#!/data/data/com.termux/files/usr/bin/bash
D=/dev/bus/usb/002/002
at() { ATECC_ARGS="-c '$*'" termux-usb -r -e ~/atecc-py/scripts/atecc-termux $D >/dev/null 2>&1; }

declare -A KEY=([10]=k10.key [11]=hmac_key.bin [12]=d_12.bin [13]=d_13.bin [14]=d_14.bin [15]=k15.key)

mkdir -p t; rm -f t/*
printf 'a' > t/01_one_byte.txt
printf 'hello world' > t/02_short.txt
printf '\xd8\xb3\xd9\x84\xd8\xa7\xd9\x85' > t/03_utf8_bytes.txt
printf 'line1\nline2\n\ttab\n' > t/04_newlines.txt
head -c 64 /dev/urandom > t/05_bin64.bin
head -c 100 /dev/zero > t/06_zeros100.bin
head -c 1000 /dev/urandom > t/07_bin1000.bin
head -c 4096 /dev/urandom > t/08_bin4096.bin
: > t/09_empty.txt

ok=0; bad=0
for s in 10 11 12 13 14 15; do
  K=${KEY[$s]}
  [ -f "$K" ] || { echo "slot $s: key file $K missing, skip"; continue; }
  for f in t/*; do
    rm -f o.bin
    at hmac-dgst $s $f o.bin
    openssl dgst -sha256 -mac HMAC -macopt hexkey:$(xxd -p -c 64 $K) -binary $f > sw.bin
    if [ ! -s o.bin ]; then r=ERR; bad=$((bad+1))
    elif cmp -s o.bin sw.bin; then r=OK; ok=$((ok+1))
    else r=DIFF; bad=$((bad+1)); fi
    printf 'slot %s  %-22s %s\n' $s $(basename $f) $r
  done
done

echo "--- cross-slot (outputs must differ) ---"
for s in 10 11 12 13 14 15; do
  rm -f o.bin; at hmac-dgst $s t/02_short.txt o.bin; cp o.bin x_$s.bin 2>/dev/null
done
for a in 10 11 12 13 14 15; do for b in 10 11 12 13 14 15; do
  [ $a -lt $b ] && { cmp -s x_$a.bin x_$b.bin && echo "SAME! $a vs $b" || true; }
done; done
echo "cross-slot check done"

echo "--- key sensitivity (flip 1 bit of key; sw must NOT match) ---"
K=${KEY[10]}
python3 -c "
k=bytearray(open('$K','rb').read()); k[0]^=1; open('kbad.bin','wb').write(k)" 2>/dev/null || echo "python3 not installed, skipped"
if [ -f kbad.bin ]; then
  openssl dgst -sha256 -mac HMAC -macopt hexkey:$(xxd -p -c 64 kbad.bin) -binary t/02_short.txt > bad.bin
  rm -f o.bin; at hmac-dgst 10 t/02_short.txt o.bin
  cmp -s o.bin bad.bin && echo "PROBLEM: matches wrong key" || echo "OK: wrong key does not match"
fi

echo "=== OK: $ok   FAIL/ERR: $bad ==="
rm -f o.bin sw.bin x_*.bin kbad.bin bad.bin
EOF
chmod +x test_hmac.sh
./test_hmac.sh
```

`OK`: chip and openssl agree. `ERR`: the chip returned nothing. `DIFF`: both
returned data but it differs (serious). Result on the tested chip: **54 of 54 OK**
(6 slots x 9 inputs, including an empty file and a 4096-byte file).

---

## 7. Slot read test: `test_read.sh`

```bash
cat > test_read.sh << 'EOF'
#!/data/data/com.termux/files/usr/bin/bash
D=/dev/bus/usb/002/002
at() { ATECC_ARGS="-c '$*'" termux-usb -r -e ~/atecc-py/scripts/atecc-termux $D 2>&1; }

declare -A KEY=([10]=k10.key [11]=hmac_key.bin [12]=d_12.bin [13]=d_13.bin [14]=d_14.bin [15]=k15.key)

leak=0; blocked=0
for s in 10 11 12 13 14 15; do
  for spec in "0 4" "0 16" "0 32" "32 32" "64 8"; do
    set -- $spec; off=$1; len=$2
    rm -f r.bin
    out=$(at read-data $s $off $len r.bin)
    if [ -s r.bin ]; then
      res="READ ${len}B"
      K=${KEY[$s]}
      if [ -f "$K" ] && [ $off -lt $(stat -c %s $K) ]; then
        if head -c $len $K | dd bs=1 skip=0 2>/dev/null | cmp -s - r.bin; then
          res="$res (EXACT KEY BYTES!)"
        fi
      fi
      echo "slot $s off=$off len=$len : $res"
      xxd r.bin | head -2
      leak=$((leak+1))
    else
      code=$(echo "$out" | grep -o 'status 0x[0-9A-Fa-f]*' | head -1)
      echo "slot $s off=$off len=$len : blocked ($code)"
      blocked=$((blocked+1))
    fi
  done
done
echo "=== blocked: $blocked   readable: $leak ==="
rm -f r.bin
EOF
chmod +x test_read.sh
./test_read.sh
```

- `blocked (0x0F)`: the read was refused (expected for secret slots 10, 11, 15).
- `READ ... EXACT KEY BYTES`: the real key came out; that slot is not suitable for secrets.
- Run it again **after `lock-data`** to see whether the non-secret slots 12-14 become readable.

---

## 8. HMAC and ECC on all 16 slots: `test_ecc_hmac.sh`

```bash
cat > test_ecc_hmac.sh << 'EOF'
#!/data/data/com.termux/files/usr/bin/bash
D=/dev/bus/usb/002/002
GEN=${GEN:-0}; GEN_ALL=${GEN_ALL:-0}
at() { ATECC_ARGS="-c '$*'" termux-usb -r -e ~/atecc-py/scripts/atecc-termux $D 2>&1; }
st() { echo "$1" | grep -o 'status 0x[0-9A-Fa-f]*' | head -1 | sed 's/status //'; }
vr() { echo "$1" | grep -o 'Verification [A-Z]*' | head -1; }

declare -A KEY=([10]=k10.key [11]=hmac_key.bin [12]=d_12.bin [13]=d_13.bin [14]=d_14.bin [15]=k15.key)
[ -f salt.bin ] || openssl rand 16 > salt.bin
echo "test message 1" > m1.txt; echo "test message 2" > m2.txt

swverify() { # sig pub msg
  python3 - "$1" "$2" <<'PY' || return 2
import sys, base64
def i(b):
    b = b.lstrip(b'\x00') or b'\x00'
    if b[0] & 0x80: b = b'\x00' + b
    return b'\x02' + bytes([len(b)]) + b
s = open(sys.argv[1], 'rb').read()
body = i(s[:32]) + i(s[32:])
open('sig.der', 'wb').write(b'\x30' + bytes([len(body)]) + body)
pub = open(sys.argv[2], 'rb').read()
der = bytes.fromhex('3059301306072a8648ce3d020106082a8648ce3d030107034200') + b'\x04' + pub
open('pub.pem', 'w').write('-----BEGIN PUBLIC KEY-----\n' + base64.encodebytes(der).decode() + '-----END PUBLIC KEY-----\n')
PY
  openssl dgst -sha256 -verify pub.pem -signature sig.der "$3" >/dev/null 2>&1
}

hmac_check() { # slot -> prints result
  local s=$1 K=${KEY[$1]} res
  rm -f h1.bin h2.bin
  local o; o=$(at hmac-dgst $s salt.bin h1.bin)
  [ -s h1.bin ] || { echo "ERR $(st "$o")"; return 1; }
  at hmac-dgst $s salt.bin h2.bin >/dev/null
  cmp -s h1.bin h2.bin && res="stable" || res="UNSTABLE"
  if [ -n "$K" ] && [ -f "$K" ]; then
    openssl dgst -sha256 -mac HMAC -macopt hexkey:$(xxd -p -c 64 $K) -binary salt.bin > sw.bin
    cmp -s h1.bin sw.bin && res="$res, matches key file" || res="$res, DIFFERS from key file"
  fi
  echo "$res"
}

echo "##### PART 1: HMAC on slots 0-15 #####"
rm -f hh_*.txt
for s in $(seq 0 15); do
  r=$(hmac_check $s)
  echo "slot $s: $r"
  [ -s h1.bin ] && case "$r" in ERR*) ;; *) sha256sum h1.bin | cut -d' ' -f1 > hh_$s.txt;; esac
done
echo "-- identical outputs between slots --"
for a in $(seq 0 15); do for b in $(seq $((a+1)) 15); do
  [ -f hh_$a.txt ] && [ -f hh_$b.txt ] && cmp -s hh_$a.txt hh_$b.txt && echo "SAME output: slot $a and slot $b"
done; done
echo "(done)"

echo; echo "##### PART 2: ECC sign on existing keys, slots 0-15 #####"
for s in $(seq 0 15); do
  rm -f sg.bin
  o=$(at ecc-sign $s m1.txt sg.bin)
  [ -s sg.bin ] && echo "slot $s: sign OK" || echo "slot $s: sign ERR $(st "$o")"
done

if [ "$GEN" = 1 ]; then
  echo; echo "##### PART 3 (GEN=1): keygen + sign + verify, slots 0-9 #####"
  for s in $(seq 0 9); do
    rm -f pub_$s.bin sg.bin
    o=$(at ecc-gen $s pub_$s.bin)
    [ -s pub_$s.bin ] || { echo "slot $s: gen ERR $(st "$o")"; continue; }
    o=$(at ecc-sign $s m1.txt sg.bin)
    [ -s sg.bin ] || { echo "slot $s: gen OK, sign ERR $(st "$o")"; continue; }
    cp sg.bin sig_$s.bin
    v1=$(vr "$(at ecc-verify $s m1.txt sg.bin pub_$s.bin)")
    v2=$(vr "$(at ecc-verify $s m2.txt sg.bin pub_$s.bin)")
    swverify sg.bin pub_$s.bin m1.txt && sw="openssl OK" || sw="openssl FAIL"
    echo "slot $s: chip[$v1] tampered[$v2] $sw"
  done
  echo "-- cross check: sig of slot 0 with pub of slot 1 (expect FAILED) --"
  [ -f sig_0.bin ] && [ -f pub_1.bin ] && vr "$(at ecc-verify 0 m1.txt sig_0.bin pub_1.bin)"
  echo "-- ECDH pairs (config says ECDH not permitted, ERR is expected) --"
  for a in 0 2 4 6 8; do
    b=$((a+1)); rm -f e_a.bin e_b.bin
    o1=$(at ecdh $a pub_$b.bin e_a.bin); o2=$(at ecdh $b pub_$a.bin e_b.bin)
    if [ -s e_a.bin ] && [ -s e_b.bin ]; then
      cmp -s e_a.bin e_b.bin && echo "ecdh $a<->$b: shared secret EQUAL" || echo "ecdh $a<->$b: secrets DIFFER"
    else echo "ecdh $a<->$b: ERR $(st "$o1") $(st "$o2")"; fi
  done
fi

if [ "$GEN_ALL" = 1 ]; then
  echo; echo "##### PART 4 (GEN_ALL=1): keygen on slots 10-15, then restore #####"
  for s in 10 11 12 13 14 15; do
    K=${KEY[$s]}; rm -f pub_$s.bin
    o=$(at ecc-gen $s pub_$s.bin)
    if [ -s pub_$s.bin ]; then
      echo "slot $s: gen OK (slot overwritten!)"
      if [ -f "$K" ]; then
        at hmac-write-key $s 0 $K >/dev/null
        echo "slot $s: restored -> $(hmac_check $s)"
      else echo "slot $s: NO key file, cannot restore!"; fi
    else echo "slot $s: gen ERR $(st "$o")"; fi
  done
fi

rm -f h1.bin h2.bin sw.bin sg.bin sig.der pub.pem e_a.bin e_b.bin hh_*.txt
echo; echo "=== finished ==="
EOF
chmod +x test_ecc_hmac.sh
./test_ecc_hmac.sh
```

Run modes:

| Command | Effect |
|---|---|
| `./test_ecc_hmac.sh` | safe: HMAC on 16 slots, `ecc-sign` on existing keys |
| `GEN=1 ./test_ecc_hmac.sh` | **generates new P256 keys** in slots 0-9 (erasing existing ones), then signs, verifies on chip, verifies with openssl, tampers the message, tests ECDH |
| `GEN_ALL=1 ./test_ecc_hmac.sh` | also runs `ecc-gen` on slots 10-15 and restores the HMAC keys from your files (likely fails per config) |

### Result on the tested chip (safe mode)
- HMAC: slots 10-15 correct; slots 0-9 returned `0x0F` (ECC-type slots, expected).
  A transient `0x0F` on slots 10 and 11 disappeared on rerun.
- `ecc-sign`: succeeded on slots 0-9, `0x0F` on 10-15 (no ECC key there).

### Verifying existing ECC keys without generating new ones
Run `echo "test message 1" > m1.txt` first.

```bash
for s in 0 1 2 3 4 5 6 7 8 9; do
  rm -f pub_$s.bin sg.bin
  o1=$(at ecc-gen-pub $s pub_$s.bin 2>&1)
  at ecc-sign $s m1.txt sg.bin >/dev/null 2>&1
  o3=$(at ecc-verify $s m1.txt sg.bin pub_$s.bin 2>&1)
  echo "slot $s: pub=$(ls -s pub_$s.bin 2>/dev/null | cut -d' ' -f1) $(echo "$o1$o3" | grep -E 'status|Verification' | tr '\n' ' ')"
done
```

All ten slots printed `Verification OK`, so each holds a valid P256 private key.
`ecc-gen-pub` derives the public key from the existing private key and does not
overwrite anything.

---

## 9. Encrypt/decrypt round trip on slots 10-15: `test_roundtrip.sh`

**Warning:** this script writes a fresh random key into every slot 10-15, which
invalidates the previous keys. By default it deletes the raw key afterwards
(`KEEP=1` keeps it).

```bash
cat > test_roundtrip.sh << 'EOF'
#!/data/data/com.termux/files/usr/bin/bash
D=/dev/bus/usb/002/002
KEEP=${KEEP:-0}
SLOTS="10 11 12 13 14 15"
at() { ATECC_ARGS="-c '$*'" termux-usb -r -e ~/atecc-py/scripts/atecc-termux $D 2>&1; }
derive() { # slot salt out
  for i in 1 2 3; do
    rm -f "$3"; at hmac-dgst $1 "$2" "$3" >/dev/null
    [ -s "$3" ] && return 0; sleep 1
  done; return 1
}
hexk() { xxd -p -c 64 "$1"; }

pass=0; fail=0
for s in $SLOTS; do
  echo "=== slot $s ==="
  printf 'secret text for slot %s: hello world\n' $s > rt_plain_$s.txt
  openssl rand 32 > rt_key_$s.bin
  at hmac-write-key $s 0 rt_key_$s.bin >/dev/null
  openssl rand 16 > rt_salt_$s.bin
  openssl rand -hex 16 > rt_iv_$s.hex

  # 1) derived key from the chip
  derive $s rt_salt_$s.bin rt_dk_$s.bin || { echo "FAIL: chip gave no derived key"; fail=$((fail+1)); rm -f rt_key_$s.bin; continue; }
  openssl dgst -sha256 -mac HMAC -macopt hexkey:$(hexk rt_key_$s.bin) -binary rt_salt_$s.bin | cmp -s - rt_dk_$s.bin \
    && echo "key written OK (chip == openssl)" || echo "WARN: chip output differs from software HMAC"

  # 2) encrypt with openssl using the derived key
  openssl enc -aes-256-cbc -K $(hexk rt_dk_$s.bin) -iv $(cat rt_iv_$s.hex) -in rt_plain_$s.txt -out rt_enc_$s.bin
  rm -f rt_dk_$s.bin
  [ "$KEEP" = 1 ] || rm -f rt_key_$s.bin
  echo "ciphertext:"; xxd rt_enc_$s.bin | head -3

  # 3) chip re-derives the key, openssl decrypts
  derive $s rt_salt_$s.bin rt_dk2_$s.bin || { echo "FAIL: second derive"; fail=$((fail+1)); continue; }
  openssl enc -d -aes-256-cbc -K $(hexk rt_dk2_$s.bin) -iv $(cat rt_iv_$s.hex) -in rt_enc_$s.bin -out rt_dec_$s.txt 2>/dev/null
  rm -f rt_dk2_$s.bin
  if cmp -s rt_plain_$s.txt rt_dec_$s.txt; then
    echo "decrypted: $(cat rt_dec_$s.txt)"; echo "RESULT: PASS"; pass=$((pass+1))
  else echo "RESULT: FAIL (decrypt mismatch)"; fail=$((fail+1)); fi

  # 4) wrong salt must not decrypt
  openssl rand 16 > rt_badsalt.bin
  derive $s rt_badsalt.bin rt_dkb.bin
  openssl enc -d -aes-256-cbc -K $(hexk rt_dkb.bin) -iv $(cat rt_iv_$s.hex) -in rt_enc_$s.bin -out rt_bad.txt 2>/dev/null
  cmp -s rt_plain_$s.txt rt_bad.txt && echo "PROBLEM: wrong salt decrypted!" || echo "wrong salt rejected: OK"
  rm -f rt_dkb.bin rt_badsalt.bin rt_bad.txt
done
echo; echo "=== PASS: $pass   FAIL: $fail ==="
EOF
chmod +x test_roundtrip.sh
./test_roundtrip.sh
```

Result on the tested chip: **`PASS: 6   FAIL: 0`**. In every slot the key was
written correctly, encryption with the derived key worked, the chip re-derived
the same key, decryption was correct, and a wrong salt was rejected.

For each slot these files remain and are needed to decrypt later:
`rt_salt_N.bin`, `rt_iv_N.hex`, `rt_enc_N.bin`.

---

## 10. Security notes and the decision to lock the data zone

### Before locking
- `lock-data` is **irreversible** and needs `--yes-lock`. The flag must reach the
  program before `-c`:
  ```bash
  ATECC_ARGS="--yes-lock -c lock-data" termux-usb -r -e ~/atecc-py/scripts/atecc-termux /dev/bus/usb/002/002
  ```
  (If this errors, check how `scripts/atecc-termux` passes its arguments.)
- After locking, the keys in slots 10, 11 and 15 cannot be rewritten (WriteConfig
  is decoded as "Never"). Write the final keys **before** locking and confirm them
  with `verify_key.sh`.
- Slots 0-9 (P256 private keys): after locking, key generation with `ecc-gen`
  stays allowed and `ecc-write` is forbidden. Decide on any specific key before locking.
- If you ran `test_roundtrip.sh`, the keys in slots 10-15 are the random test
  keys. Write your final keys again for real use.

### Key storage
- A raw key file on the phone means anyone with that file can compute the same
  derived keys without the chip.
- If you delete the key file and the chip is lost or damaged, all encrypted data
  is permanently lost.
- Choose between "key only on the chip" and "recoverable".

### Security before locking
While the data zone is unlocked, anyone with access to the chip can overwrite
slot keys. Real security only exists after locking and testing.

### Recommended slots for real use
- **11 and 15**: config is exactly HMAC and secret (one for key derivation, the
  other e.g. for a MAC/integrity tag).
- **10**: AES type that also produced HMAC before locking; it may stop working
  after locking, so treat it as a bonus.
- **12-14**: not secret (`IsSecret=0`) and may become readable after locking.
  Do not use them for encryption keys.
- **0-9**: P256 keys for **signing** (ECDH is disabled in this config, so
  asymmetric encryption such as ECIES is not possible).

### Testing after locking
If you have a second chip, test there first: write the config and lock it, write
test keys, run `lock-data`, then run `test_hmac.sh`, `test_read.sh` and
`verify_key.sh`. `test_roundtrip.sh` cannot write keys after locking.

---

## 11. Quick troubleshooting

| Symptom | Meaning / action |
|---|---|
| `status 0x0F` on `read-data` of a secret slot | expected (reads forbidden) |
| `status 0x0F` on `hmac-dgst` or `write-data` | often transient; run again |
| `status 0x03` on `aes` | the AES command does not work on the tested chip; use the HMAC method |
| `status 0xF0` or `0xF4` | communication error; rerun the command |
| `warning: could not take the ATECC session lock` | session-lock warning, mostly harmless |
| `No such file` with `\~` | write plain `~` instead of `\~` |
| persistent `ERR` or `chip gave no output` | check `at data-is-locked` and `at slot-is-locked N` |
| `MISMATCH` in `verify_key.sh` | key differs from the file; rewrite and verify again |

### Cleaning up test files
```bash
rm -f c_*.bin s_*.bin r_*.bin d_*.bin rd_*.bin h_*.bin hs_*.bin t10.bin t11.bin k10b.bin k11.bin
rm -rf t
```
(`k10.key`, `k15.key`, `hmac_key.bin` and `d_12.bin`-`d_14.bin` are key files;
delete them only if you no longer need them.)
