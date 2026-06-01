# TPMS PortaPack Bench Test

Synthetic Schrader-family TPMS packets you can replay with a HackRF + PortaPack
to verify the CYM-NM28C5 TPMS decoder **without needing a real car**.

## Files

| File | Freq | Pressure | Temp | Flag |
|------|------|----------|------|------|
| `tpms_315MHz_DEADBEEF_normal.C16`     | 315 MHz | 33.0 PSI / 228 kPa | 25 °C | 0x00 |
| `tpms_433MHz_DEADBEEF_normal.C16`     | 433 MHz | 33.0 PSI / 228 kPa | 25 °C | 0x00 |
| `tpms_315MHz_DEADBEEF_lowpressure.C16`| 315 MHz | 24.0 PSI / 165 kPa | 28 °C | 0x08 |

Sensor ID for all files: `DEADBEEF`

The low-pressure file (24.0 PSI) is below the 28 PSI threshold and should turn the
sensor card **amber** on the TPMS Monitor screen. The normal files (33.0 PSI) should
appear **green**.

## PortaPack Replay Settings

1. Copy the `.C16` file to the PortaPack SD card (any location)
2. On the PortaPack: **Replay** app
3. Set these parameters:

   | Setting | Value |
   |---------|-------|
   | Center frequency | **315.000 MHz** or **433.000 MHz** (match the file) |
   | Sample rate | **500k** (500,000 samples/sec) |
   | TX gain | **35 dB or higher** |

4. Press play — the file loops automatically

## CYM-NM28C5 Setup

1. Open the **CC1101 menu → TPMS Monitor**
2. Select **315 MHz US** or **433 MHz EU** to match the file you are replaying
3. Tap **Start**
4. Within a few seconds `DEADBEEF` should appear as a sensor card

Expected display:
```
DEADBEEF        33.2 PSI / 228 kPa
+25°C   -XX dBm   [OK]   Xs ago
```
(PSI may read 33.2 instead of 33.0 — the raw-to-PSI conversion rounds to the
nearest 0.36 PSI step, so ±0.2 PSI rounding is normal.)

For the low-pressure file:
```
DEADBEEF        24.0 PSI / 165 kPa     ← amber card
+28°C   -XX dBm   [OK]   Xs ago
```

## Signal Format (for reference)

Generated with `tools/gen_tpms_c16.py`. Schrader EG53MA4-compatible OOK signal:

| Parameter | Value |
|-----------|-------|
| Modulation | OOK / ASK |
| Data rate | 9,970 baud |
| Preamble | 56 bits `0xAA AA AA AA AA AA AA` |
| Sync word | `0xD391` |
| Payload | 8 bytes: `ID[4] \| pressure[1] \| temp[1] \| flags[1] \| crc8[1]` |
| Repetitions | 3 bursts per transmission |
| Sample rate | 500,000 sps |

Pressure encoding: `raw = round(PSI / 0.36)`, Temperature: `raw = °C + 40`

CRC-8 polynomial: `0x07`, no pre/post invert, MSB first.

## Regenerating Files

```bash
cd tools
python3 gen_tpms_c16.py --freq 315 --psi 33.0 --temp 25 --id DEADBEEF
python3 gen_tpms_c16.py --freq 433 --psi 33.0 --temp 25 --id DEADBEEF
python3 gen_tpms_c16.py --freq 315 --psi 24.0 --temp 28 --id DEADBEEF --flags 0x08
```

Use `--id` with any 8-digit hex sensor ID you want to see on screen.
