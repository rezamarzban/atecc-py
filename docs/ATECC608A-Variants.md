# ATECC608A Ordering Variants

This document lists the ATECC608A package, interface, and ordering-code variants documented by Microchip.

## Standard catalog order codes

| Full order code | Package | Interface | Packing option |
|---|---|---|---|
| `ATECC608A-SSHDA-B` | 8-lead SOIC | I²C | Tube (100 per tube) |
| `ATECC608A-SSHDA-T` | 8-lead SOIC | I²C | Large tape-and-reel (4,000 per reel) |
| `ATECC608A-SSHCZ-B` | 8-lead SOIC | Single-Wire (SWI) | Tube (100 per tube) |
| `ATECC608A-SSHCZ-T` | 8-lead SOIC | Single-Wire (SWI) | Large tape-and-reel (4,000 per reel) |
| `ATECC608A-MAHDA-S` | 8-pad UDFN, 2 × 3 mm | I²C | Small tape-and-reel (3,000 per reel) |
| `ATECC608A-MAHDA-T` | 8-pad UDFN, 2 × 3 mm | I²C | Large tape-and-reel (15,000 per reel) |
| `ATECC608A-MAHCZ-S` | 8-pad UDFN, 2 × 3 mm | Single-Wire (SWI) | Small tape-and-reel (3,000 per reel) |
| `ATECC608A-MAHCZ-T` | 8-pad UDFN, 2 × 3 mm | Single-Wire (SWI) | Large tape-and-reel (15,000 per reel) |

## Ordering-code breakdown

The standard ordering-code structure is:

```text
ATECC608A-<package><interface>-<packing>
```

| Code | Meaning |
|---|---|
| `SSH` | 8-lead SOIC package |
| `MAH` | 8-pad UDFN package (2 × 3 × 0.6 mm) |
| `CZ` | Single-Wire Interface (SWI) |
| `DA` | I²C interface |
| `B` | Tube packaging |
| `T` | Large tape-and-reel |
| `S` | Small tape-and-reel; available only with the `MAH` package |

## Additional package option

Microchip also documents `W07` as a **die-on-tape-and-reel** package option. It is available only to qualified customers and must be custom-ordered. The datasheet says this option is available with either I²C or Single-Wire I/O, with a minimum reel size of 10,000 units. Contact Microchip for availability and ordering details.

## Recommendation for an I²C prototype

For a design using I²C and a conventional, hand-solderable package, use:

**`ATECC608A-SSHDA-B` — SOIC-8, I²C, supplied in tubes.**

The `SSHDA` portion identifies the SOIC package and I²C interface; the final `B` identifies tube packaging. The packing suffix is part of the catalog order code and is not printed on the chip package.

## Official references

- [Microchip ATECC608A product page and catalog parts](https://www.microchip.com/en-us/product/atecc608a)
- [Microchip ATECC608A CryptoAuthentication Device Summary Datasheet (DS40001977B), Product Identification System, page 25](https://www.microchip.com/content/dam/mchp/documents/SCBU/ProductDocuments/DataSheets/ATECC608A-CryptoAuthentication-Device-Summary-Data-Sheet-DS40001977B.pdf)

---

*Order-code definitions and package options are based on Microchip datasheet DS40001977B, page 25. Confirm current stock and availability with Microchip or an authorized distributor before purchasing.*
