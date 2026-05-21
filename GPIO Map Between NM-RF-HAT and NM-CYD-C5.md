# NM-RF-HAT ↔ NM-CYD-C5 GPIO Map

**Connector:** 14-pin FPC2 flat-flex (NM-RF-HAT → NM-CYD-C5)  
**Source:** Verified against `SCH_NM-RF-HAT_v1.0.pdf` and `SCH_NM-CYD-C5-v1.0.pdf`  
**IR/RF433 TX/RX assignment:** Empirically confirmed by LED observation (v1.8.35, 2026-05-21)

---

## FPC2 Connector Pinout

| FPC2 Pin | RF-HAT Label | NM-CYD-C5 GPIO | Function on RF-HAT               |
|----------|--------------|----------------|-----------------------------------|
| 1        | IO19         | GPIO2          | SPI MISO (shared bus)             |
| 2        | IO18         | GPIO6          | SPI CLK  (shared bus)             |
| 3        | IO23         | GPIO7          | SPI MOSI (shared bus)             |
| 4        | IO5          | GPIO10         | SPI CS — SD card (always active)  |
| 5        | GND          | GND            | —                                 |
| 6        | IO21         | GPIO4          | Not used by any RF module         |
| 7        | IO22         | GPIO8          | Multi-role data line A (see below)|
| 8        | IO35         | GPIO5          | Not used by any RF module         |
| 9        | IO27         | GPIO9          | Multi-role data line B (see below)|
| 10       | USB D−       | USB D−         | —                                 |
| 11       | USB D+       | USB D+         | —                                 |
| 12–14    | GND          | GND            | —                                 |

---

## DIP Switch → Module → GPIO Role

Only **GPIO8** (IO22, Pin 7) and **GPIO9** (IO27, Pin 9) carry per-module data signals.
DIP switches cut VCC to inactive modules via AO3401A P-channel MOSFETs — no firmware
mux needed and no bus leakage from unpowered modules.

| DIP | Module           | GPIO8 (IO22 / Pin 7)            | GPIO9 (IO27 / Pin 9)           |
|-----|------------------|---------------------------------|---------------------------------|
| 1   | CC1101 Sub-GHz   | GDO0 — interrupt output         | CSN — SPI chip select           |
| 2   | nRF24L01 2.4 GHz | CE — chip enable (active HIGH)  | CSN — SPI chip select           |
| 3   | PN532 NFC/RFID   | SCL — I2C clock                 | SDA — I2C data (bidirectional)  |
| 4   | IR Infrared      | **IR_DT — TX emitter** ✓       | **IR_DR — RX detector** ✓      |
| 5   | RF433 OOK/ASK    | **433_DT — TX drive** ✓        | **433_DR — RX input** ✓        |
| 6   | Battery switch   | (power only, no GPIO)           | (power only, no GPIO)           |

> **IR/RF433 GPIO note:** The schematic labels IR_DT and 433_DT on the IO27/GPIO9 net,
> but physical testing with the NM-CYD-C5 confirmed the **green emitter LED is on GPIO8**
> and the **blue detector LED is on GPIO9**. The firmware defines match this empirical
> result. DIP 4 and DIP 5 share the same GPIO8/GPIO9 nets.

---

## GPIO Conflict Summary

```
            GPIO2   GPIO6   GPIO7   GPIO8   GPIO9   GPIO10
            MISO    CLK     MOSI    IO22    IO27    SD-CS
DIP 1       ████    ████    ████    GDO0    CSN     ░░░░    CC1101
DIP 2       ████    ████    ████    CE      CSN     ░░░░    nRF24L01
DIP 3       ░░░░    ░░░░    ░░░░    SCL     SDA     ░░░░    PN532
DIP 4       ░░░░    ░░░░    ░░░░    IR-TX   IR-RX   ░░░░    IR
DIP 5       ░░░░    ░░░░    ░░░░    RF-TX   RF-RX   ░░░░    RF433
SD card     ░░░░    ████    ████    ░░░░    ░░░░    ████    always

████ = active   ░░░░ = idle
```

---

## Firmware Defines (`rf_hat_config.h`)

```c
// SPI shared bus — all SPI modules (CC1101, nRF24, display, SD)
//   MISO = GPIO2   CLK = GPIO6   MOSI = GPIO7

// CC1101 Sub-GHz (DIP 1)
#define RF_HAT_CC1101_CS_GPIO    9   // IO27 — CSN_CC1101
#define RF_HAT_CC1101_GDO0_GPIO  8   // IO22 — GDO0_CC1101

// nRF24L01 2.4 GHz (DIP 2)
#define RF_HAT_NRF24_CS_GPIO     9   // IO27 — NRF24_CSN
#define RF_HAT_NRF24_CE_GPIO     8   // IO22 — NRF24_CE

// PN532 NFC/RFID I2C (DIP 3)
#define RF_HAT_PN532_SDA_GPIO    9   // IO27 — SDA
#define RF_HAT_PN532_SCL_GPIO    8   // IO22 — NSS/SCL_PN532

// IR Infrared (DIP 4) — confirmed by green/blue LED observation
#define RF_HAT_IR_TX_GPIO        8   // IO22 / Pin 7 — emitter (green LED)
#define RF_HAT_IR_RX_GPIO        9   // IO27 / Pin 9 — detector (blue LED)

// RF433 OOK/ASK (DIP 5) — same physical nets as IR
#define RF_HAT_RF433_TX_GPIO     8   // IO22 / Pin 7 — TX drive
#define RF_HAT_RF433_RX_GPIO     9   // IO27 / Pin 9 — RX input
```

---

## RMT Peripheral Constraints (ESP32-C5)

The IR TX and RF433 RX drivers both use the ESP32-C5 RMT peripheral.

- ESP32-C5 has **4 RMT channels**: TX = ch0/ch1, RX = ch2/ch3
- `SOC_RMT_MEM_WORDS_PER_CHANNEL = 48` — **not 64**
- Setting `mem_block_symbols > 48` causes the channel to chain an adjacent slot,
  consuming both RX channels and leaving none for IR capture
- WS2812 (GPIO27, onboard LED) also uses an RMT TX channel — keep `mem_block_symbols = 48`
  on all three RMT users (WS2812 TX, IR TX, IR RX) to avoid resource exhaustion

---

## Pins Not Used by Any RF Module

GPIO4 (IO21 / FPC2 Pin 6) and GPIO5 (IO35 / FPC2 Pin 8) pass through the FPC2
connector and are broken out to a secondary 4-pin JST header on the HAT, but are
not connected to CC1101, nRF24, PN532, IR, or RF433.

---

## Version History

| Date       | Change                                                              |
|------------|---------------------------------------------------------------------|
| 2026-05-14 | Initial GPIO map created from schematic cross-reference             |
| 2026-05-21 | IR TX/RX GPIO corrected from empirical LED observation (v1.8.35):  |
|            | GPIO8 = TX emitter, GPIO9 = RX detector (opposite of schematic label). |
|            | RF433 TX/RX corrected to match (same physical nets as IR).          |
|            | RMT mem_block_symbols constraint documented (48 max on ESP32-C5).  |
