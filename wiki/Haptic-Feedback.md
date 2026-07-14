# Haptic Feedback

CYM includes an optional **ERM (eccentric rotating mass) vibrator motor** driven through the onboard SC8002B class-D audio amplifier on the SPEAK header (GPIO 26). Because the alert is completely non-audible, it lets you operate the device in occupied or sensitive environments — pocket, bag, or flat on a desk — without drawing attention.

---

## Features That Use Haptic

| Feature | Pattern | Behaviour |
|---------|---------|-----------|
| **BT Lookout** | 3 × 1-second bursts, 500 ms gaps | Fires on every watchlist MAC/OUI match |
| **BT Locator** | Continuous pulse every 500 ms | Strength scales 10–100% with RSSI |
| **WiFi Deauth** | 1 × 3-second solid pulse | Fires at attack launch as non-audible confirmation |
| **CC1101 Fox Hunt** | 150 ms bursts, 100% strength | Pulse *rate* scales with signal level |
| **nRF24 Fox Hunt** | 150 ms bursts, 100% strength | Pulse *rate* scales with carrier detect rate |
| **RF433 Fox Hunt** | 150 ms bursts, 100% strength | Pulse *rate* scales with 433 MHz edge activity |

### BT Locator RSSI → strength table

| RSSI | Approximate distance | Motor strength |
|------|----------------------|----------------|
| −40 dBm or stronger | Within ~1 m | 100% |
| −55 dBm | ~1–3 m | ~58% |
| −69 dBm | ~5 m (edge of range) | 10% |
| Below −69 dBm | Too far / obstructed | Silent |

Strength updates every 500 ms. The formula is linear in dBm: `strength = 10 + (RSSI + 69) × 90 / 29`, clamped to 10–100 %.

---

## Hardware — Build Instructions

The vibrator is an **optional hardware add-on**. The firmware detects it automatically — if the motor is not installed, all haptic calls are no-ops.

### Parts

| Role | Part | Notes |
|------|------|-------|
| Series rectifier | 1N5819 Schottky diode | Anode → VO1 (SPEAK pin 1), cathode → motor +. Half-wave rectifies the BTL output. |
| Flyback protection | 1N4148 signal diode | Cathode → motor +, anode → motor −. Suppresses back-EMF spikes on each PWM off-cycle. |
| Motor | Mini ERM vibration motor, 3 V nominal | Coin or cylindrical form factor. |
| Header connector | JST GH **1.25 mm** 2-pin | **1.25 mm pitch only** — the 1.0 mm SH connector is too small and will not fit. |

> **Why the SC8002B amp?** ERM motors draw 100–200 mA at startup, well beyond the ~20 mA continuous GPIO limit. The SC8002B buffers the GPIO signal and drives up to ~1.5 A peak from the board's power rail. GPIO 26 sources only ~1 mA into the amp input. Never connect a motor directly to a GPIO pin.

### Circuit

The SC8002B outputs a BTL (bridge-tied load) differential signal. The 1N5819 half-wave rectifies it so the motor sees clean DC-biased pulses. The 1N4148 flyback diode clamps the inductive spike produced by the motor on each PWM off-cycle — without it, the spike would damage the SC8002B output stage.

**PWM parameters:** LEDC timer, 333 Hz, 8-bit. Maximum effective duty is **50%** (the BTL half-wave rectification means higher duty gives no additional torque). Strength slider in Settings → Vibrator Test maps 10–100% → 13–128/255 duty counts.

### Assembly photos

<p align="center">
  <img src="../docs/screenshots/Vibrator Rectifier Circuit Closeup.jpg" width="480" alt="Rectifier circuit — 1N5819 series + 1N4148 flyback"/>
  <br/><em>Rectifier circuit — 1N5819 series diode and 1N4148 flyback</em>
</p>

<p align="center">
  <img src="../docs/screenshots/Vibrator Wireup.jpg" width="480" alt="Motor wired to SPEAK header with diode circuit"/>
  <br/><em>Motor wired to SPEAK header with diode circuit in place</em>
</p>

<p align="center">
  <img src="../docs/screenshots/Vibrator Wraped.jpg" width="480" alt="Assembly wrapped for installation"/>
  <br/><em>Assembly wrapped and ready to install</em>
</p>

<p align="center">
  <img src="../docs/screenshots/Vibrator Installed.jpg" width="480" alt="Motor installed in device"/>
  <br/><em>Motor installed in the device</em>
</p>

---

## Testing & Calibration

**Settings → Vibrator Test** exposes:
- **ON / OFF** buttons — manual control for confirming the motor is wired and working
- **Strength slider** (10–100%) — adjusts duty cycle in real time while running; lets you find the minimum strength that reliably spins the motor in your specific motor/mounting combination

The strength setting persists within the session. BT Locator saves and restores your test strength so the locator's RSSI-scaled range isn't affected by a prior test value.

---

## Operational Tips

- **Fox Hunt / BT Locator in a jacket pocket** — the variable pulse rate is easy to read by feel after a few minutes of practice. Faster = closer, stronger = closer. You can navigate to a target without ever looking at the screen.
- **BT Lookout during a walk-through** — the 3-burst pattern is distinctive and hard to confuse with accidental contact. Hold the device loosely; the bursts transmit clearly through fabric.
- **Deauth confirmation** — the 3-second solid pulse means you felt the attack launch without looking down. Useful when you're watching a target's screen for client drops while simultaneously operating CYM.
