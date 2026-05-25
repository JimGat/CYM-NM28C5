# CYM-NM28C5 Smoke Test Checklist

Run this before declaring any build stable. Flash via ESPConnect from the
`Jimgat_Dev` branch on GitHub, then work through each section. Mark each
item P (pass), F (fail), or S (skip — feature not reachable in this session).

**Build:** ____________  **Date:** ____________  **Tester:** ____________

---

## 1. Boot

| # | Check | Result |
|---|-------|--------|
| 1.1 | Splash screen appears within 3 s of power-on | |
| 1.2 | WS2812 LED changes color during boot sequence | |
| 1.3 | Backlight stays on after splash | |
| 1.4 | Home screen renders — no blank tiles, no garbled text | |
| 1.5 | Serial log shows firmware version matching the build | |
| 1.6 | No `E` (error) or `W` (warning) lines in the first 10 s of log | |

---

## 2. Touch

| # | Check | Result |
|---|-------|--------|
| 2.1 | Tapping each quadrant of the home screen registers correctly | |
| 2.2 | No dead zone on right or top edge | |
| 2.3 | Long-press / hold-to-scroll works in list screens (BT, WiFi) | |
| 2.4 | Back / Home navigation returns to home screen without crash | |

> If touch feels off: Settings → Screen → Recalibrate Touch.

---

## 3. SD Card

| # | Check | Result |
|---|-------|--------|
| 3.1 | Serial log shows `sdmmc: ... SD card size:` at boot | |
| 3.2 | File Browser tile opens and lists `/sdcard` contents | |
| 3.3 | A file can be downloaded via the web file server | |

---

## 4. WiFi

| # | Check | Result |
|---|-------|--------|
| 4.1 | WiFi Scanner finds at least one AP | |
| 4.2 | Results show both 2.4 GHz and 5 GHz entries (dual-band) | |
| 4.3 | Selecting an AP shows RSSI, BSSID, channel | |
| 4.4 | Scan completes without hanging the UI | |

---

## 5. BLE

| # | Check | Result |
|---|-------|--------|
| 5.1 | BT Scanner runs and finds 10+ devices (typical indoor environment) | |
| 5.2 | Device list shows names / MACs / RSSI | |
| 5.3 | GATT Walker connects to a device and saves a JSON file to SD | |
| 5.4 | BT Lookout — add a test device, run a scan, verify watchlist hit vibrates | |
| 5.5 | Returning to Home after BT does not crash or freeze WiFi | |

---

## 6. IR (NM-RF-HAT, DIP 4)

| # | Check | Result |
|---|-------|--------|
| 6.1 | IR Capture: green emitter LED is dark; blue detector LED blinks on signal | |
| 6.2 | Capture records a signal from a real remote (count > 0) | |
| 6.3 | Saved signal appears in the remote file list on SD | |
| 6.4 | Replay: green emitter LED blinks; captured signal turns off target device | |
| 6.5 | TV-B-Gone runs all codes without crashing | |
| 6.6 | Second capture after a cancel does not log "channel not in enable state" | |

---

## 7. RF 433 MHz (NM-RF-HAT, DIP 5)

| # | Check | Result |
|---|-------|--------|
| 7.1 | RF433 Capture records a signal from a 433 MHz device | |
| 7.2 | Replay transmits (check with a 433 MHz receiver or SDR) | |
| 7.3 | Saved `.sub` file is Flipper-compatible format | |

---

## 8. CC1101 Sub-GHz (NM-RF-HAT, DIP 1)

| # | Check | Result |
|---|-------|--------|
| 8.1 | CC1101 menu opens; 2-page tile layout renders correctly | |
| 8.2 | HW Test: STATUS shows valid (not 0x00 or 0xFF); PARTNUM=0x00; VERSION=0x14 | |
| 8.3 | Freq Scan: canvas renders; spectrum bars appear; active-channel count > 0 | |
| 8.4 | RAW Capture: 10 s window; Save prompt appears; file saved to /sdcard/lab/radio/ | |
| 8.5 | Saved Files: .sub file from 8.4 appears in list; Play executes without error | |
| 8.6 | Band Scope: spectrum + waterfall canvas update continuously without crash | |
| 8.7 | Jammer: disclaimer screen appears; Back returns cleanly without activating | |

---

## 8b. PN532 NFC/RFID (NM-RF-HAT, DIP 3)

| # | Check | Result |
|---|-------|--------|
| 8b.1 | RFID menu opens; Scan screen shows "Ready - hold card near antenna" | |
| 8b.2 | Tap Scan and hold an NFC card: UID, ATQA, SAK, type appear on screen | |
| 8b.3 | Tap Save; name popup appears; card saves to /sdcard/lab/rfid/hf/ | |
| 8b.4 | Export .nfc: file appears in /sdcard/lab/rfid/export/ | |
| 8b.5 | Saved Cards: saved card appears in list; Load restores card data | |
| 8b.6 | Emulate: selecting a saved card and tapping Emulate runs without crash | |

---

## 8c. nRF24L01+ 2.4 GHz (NM-RF-HAT, DIP 2)

| # | Check | Result |
|---|-------|--------|
| 8c.1 | nRF24 menu opens; 2-page tile layout renders correctly | |
| 8c.2 | HW Test: STATUS shows valid (not 0x00 or 0xFF); registers read without error | |
| 8c.3 | Ch Scan: canvas renders; spectrum + waterfall update; active-channel count shown | |
| 8c.4 | Sniffer: starts without crash; status updates; stop returns cleanly | |
| 8c.5 | Jammer: disclaimer screen appears; Back returns cleanly without activating | |
| 8c.6 | Futaba S-FHSS: scan starts; result displayed (or "not found" after timeout) | |

---

## 9. GPS

| # | Check | Result |
|---|-------|--------|
| 9.1 | GPS tile shows "Waiting for fix" or a valid coordinate (not crash) | |
| 9.2 | With fix: latitude/longitude update in real time | |

---

## 10. Wardrive

| # | Check | Result |
|---|-------|--------|
| 10.1 | Wardrive starts, scans APs, writes entries to SD | |
| 10.2 | Output file is valid WiGLE CSV or KML format | |
| 10.3 | Stopping wardrive returns to home without hang | |

---

## 11. Vibrator

| # | Check | Result |
|---|-------|--------|
| 11.1 | Settings → Vibrator Test → ON produces buzz | |
| 11.2 | Strength slider changes intensity visibly | |
| 11.3 | OFF stops immediately | |

---

## 12. Settings & NVS

| # | Check | Result |
|---|-------|--------|
| 12.1 | Screen timeout slider saves and survives reboot | |
| 12.2 | Dark mode toggle persists across reboot | |
| 12.3 | RF HAT enable/disable toggle saves | |

---

## 13. Memory (check serial log)

| # | Check | Result |
|---|-------|--------|
| 13.1 | PSRAM free at boot > 7 MB | |
| 13.2 | After a BT scan + GATT walk: PSRAM free > 6.5 MB | |
| 13.3 | After an IR capture + replay session: no RMT errors in log | |
| 13.4 | After 10 min of mixed use: heap free has not collapsed | |

---

## Known Skip Conditions

- **Wardrive Upload** (Settings → Data Transfer) — placeholder, not implemented.
- **Battery level** — ADC disabled; shows nothing. Not a failure.
- **DIP-exclusive HAT modules** — only one of IR/RF433/CC1101/nRF24/PN532 can be
  active at a time (hardware power exclusion). Test only the one with DIP on.
- **nRF24 stub screens** (MouseJack, Kb Inject, Drone, GamePad) — show Coming Soon screens; no RF functionality yet.

---

## Notes / Failures

```
[record regressions, unexpected behavior, or environment notes here]
```
