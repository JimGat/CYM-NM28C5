# Sub-GHz RF Research (CC1101)

> **Requires:** NM-RF-HAT with DIP 1 ON.  
> **Hardware:** CC1101RGPR directly on the RF-HAT PCB. LC-filtered antenna, no external PA. Max output ~+12 dBm. Range varies by environment — expect tens of metres for most OOK targets.

The CC1101 is a single-chip RF transceiver covering **300–928 MHz** with programmable modulation (OOK, 2-FSK, GFSK, MSK). On CYM this unlocks a large slice of the sub-GHz attack surface used by garage openers, key fobs, alarm sensors, weather stations, smart meters, Z-Wave, and more.

---

## Band Scope — Spectrum Visualiser

<!-- screenshot: band_scope.png -->

A real-time **40-bin spectrum + waterfall** display across a configurable frequency range.

### What it shows
- RSSI heat-map per bin, updated continuously
- Waterfall (time history) scrolling downward so brief transmissions leave a visible trail
- Tap any bin to read the exact centre frequency and instantaneous RSSI

### Research use cases

**Discovering unknown transmitters**  
Point CYM at a 433 MHz band and watch the waterfall while walking through a building. Any keyfob press, door sensor trigger, or temperature sensor heartbeat leaves a streak at the exact frequency — letting you locate and narrow in on targets before capturing.

**Confirming capture setup**  
Before committing to a long capture session, verify that your target frequency is actually active and that the signal amplitude reaches above the noise floor visible in the scope.

**Channel occupancy survey**  
Regulatory 433 MHz ISM is shared by dozens of device classes. A 5-minute Band Scope session shows which sub-bands are most congested, useful before deploying your own ISM devices or when diagnosing interference on customer equipment.

**Z-Wave band check**  
Verify 908.42 MHz (US) activity before running Z-Wave Scout — confirms the CC1101 antenna is resonant at that frequency and that Z-Wave nodes are transmitting.

### Field scenario

You're doing a physical assessment of a distribution warehouse. The client uses 433 MHz wireless door sensors and a keypad-armed alarm system. You open Band Scope on 433 MHz and watch the waterfall. Every time a forklift passes a dock sensor you see a spike light up and trail downward — pinpointing the exact frequency in seconds. You lock in on it and switch to Capture before you've even introduced yourself to the site manager.

---

## Capture — Raw Signal Recording

<!-- screenshot: cc1101_capture.png -->

Records a raw IQ stream from the CC1101 RX for up to **10 seconds**, then auto-saves to `/sdcard/lab/cc1101/` in Flipper Zero `.sub` file format.

### What it saves
Each `.sub` file contains the alternating mark/space pulse durations in microseconds — the same format Flipper Zero uses, so files are directly portable.

### Research use cases

**Rolling-code analysis baseline**  
Capture a known-good keyfob press. Even if you cannot replay a rolling code, having the raw capture lets you confirm the modulation, chip rate, preamble structure, and frame length. Compare two consecutive presses to observe the counter increment in the data payload.

**Alarm sensor fingerprinting**  
Most 433 MHz wireless alarm PIRs, door contacts, and smoke detectors use fixed-code OOK (EV1527 or similar). A single capture is enough to identify the 24-bit address and decode the channel bits. CYM's built-in EV1527 decoder (CC1101 Alarm Sensor tile) does this automatically.

**Protocol reverse engineering**  
For devices that don't match a known decoder, the raw `.sub` file can be imported into Universal Radio Hacker (URH) or inspected in Audacity to manually identify preamble, sync word, data encoding, and CRC position.

**Fleet/audit logging**  
Capture multiple sensors in sequence, naming each file by location. The SD card becomes a timestamped evidence trail of every wireless device found during a physical security assessment.

### Field scenario

Same warehouse. You hit Capture, walk past the dock door once, and wait ten seconds. The `.sub` file lands on the SD card. You name it `dock_door_open`. That's it. The entire capture — frequency, modulation, pulse timings, everything — is now saved in a Flipper-compatible file. The alarm system uses fixed-code OOK. One signal. Captured in one pass. No protocol knowledge required, no decoding, no reverse engineering. Just a recording of what the real remote does.

---

## Replay — Signal Retransmission

<!-- screenshot: cc1101_replay.png -->

Browses your saved `.sub` files by remote name → signal, then retransmits at the original frequency and modulation. Supports **×1 / ×3 / ×5** repeat modes.

### Research use cases

**Fixed-code vulnerability demonstration**  
After capturing a garage door opener or alarm remote, replay the capture to demonstrate that the device accepts the replay. This is the canonical proof-of-concept for fixed-code OOK vulnerabilities. Always do this only in authorized assessments — the replay proves the attack works without needing to reverse-engineer the protocol.

**Sensor spoofing test**  
Replay a captured alarm sensor signal to verify whether the alarm panel accepts duplicate transmissions (replay attack surface). Panels with rolling-counter or timing validation should reject replays.

**Range and power testing**  
Transmit a known signal at varying distances from your target receiver and note at what distance reception fails. Gives you a realistic RF budget estimate for the attack path.

### Field scenario

Two hours after the capture. You walk back to the dock door — no remote, no keyfob, no social engineering required. You select `dock_door_open` from the file list, hit Replay, and the door opens. The alarm panel disarms. You just demonstrated that the entire perimeter security system runs on fixed-code OOK with zero replay protection, using a device that cost less than a cup of coffee. That finding goes in the report as critical.

---

## Frequency Scan — Channel Survey

<!-- screenshot: cc1101_freqscan.png -->

Steps across a programmable list of frequencies, dwells briefly on each, and displays RSSI. A three-page tile UI lets you move through 315 / 433 / 868 / 915 MHz presets.

### Research use cases

**Finding an unknown device's transmit frequency**  
When you have a target device but don't know its frequency, the scan will light up the correct channel when the device transmits. Useful for unlabelled OEM devices, cloned/counterfeit keyfobs, or devices outside the "standard" ISM sub-bands.

**Multi-band ISM audit**  
A single pass across 315, 433, 868, and 915 MHz identifies which bands are in use in the target environment, helping focus deeper analysis.

### Field scenario

You have a target device but no datasheet and no markings beyond a regulatory ID. You know it's sub-GHz. You run Frequency Scan across 315, 433, 868, and 915 MHz presets while standing next to it and triggering it manually. On the third press the 915 MHz scan lights up a channel that wasn't there before. You now have the transmit frequency, and you can switch directly to Capture from here.

---

## Z-Wave Scout — Smart Home Discovery

<!-- screenshot: zwave_scout.png -->

Listens passively on **908.42 MHz** (US) using GFSK 9.6 kbps — the Z-Wave primary channel — and logs every frame observed to `/sdcard/lab/zwave/`.

### What it logs
- Frame byte sequences in hex
- RSSI at time of reception
- Timestamp

### Research use cases

**Smart home infrastructure enumeration**  
Walk a property during a physical assessment with Z-Wave Scout running. Every Z-Wave lock, dimmer, sensor, or thermostat that transmits will appear in the log, along with its Node ID and Home ID embedded in the Z-Wave MAC header. This passively identifies the home ID (network identifier) without joining the mesh.

**Protocol compliance check**  
Verify that a Z-Wave device is actually transmitting on the correct channel and with the expected GFSK parameters — catches devices that use non-standard channel offsets or baud rates.

**Frame timing analysis**  
Z-Wave uses ACK-required unicast. Watching the scout log lets you observe request/ACK pairs and identify nodes that are slow to respond or not ACKing — useful for diagnosing mesh health on a network you manage.

### Field scenario

Corporate office building, physical security assessment. Nobody mentioned Z-Wave in the scope documentation. You open Z-Wave Scout and walk the building for ten minutes. The log comes back with seven unique Home IDs and dozens of Node IDs — thermostats, motorized blinds, smart lighting controllers, and a Z-Wave lock on the executive suite. The client's IT team has zero visibility into any of it. The building management contractor installed it three years ago and never told anyone. Z-Wave Scout found all of it passively, without joining any mesh, without sending a single command frame.

---

## Fox Hunt — Sub-GHz Signal Direction Finding

<!-- screenshot: cc1101_foxhunt.png -->

Tunes to a configurable frequency (300–928 MHz) and continuously displays RSSI with an adjustable squelch threshold. A **Hunt button** locks the tuning and switches the display to a signal-strength bar optimised for direction finding. **Haptic feedback fires on every signal detection above squelch** — 150 ms vibration bursts at full motor strength, with the pulse rate scaling proportionally to signal level. Stronger signal = faster pulses.

Fine-tune controls let you step ±1 kHz or ±10 kHz while hunting, and the frequency and squelch settings persist across screen navigations.

### Research use cases

**Locating an unknown sub-GHz transmitter**  
After Band Scope identifies an active frequency, switch to Fox Hunt on that frequency and walk toward the signal. The haptic pulse rate guides you by feel — faster buzzing means you're moving toward the source. No need to watch the screen; keep the device in a pocket or bag.

**Rogue transmitter hunt during facility assessment**  
Sub-GHz wireless bugs, covert RF exfiltration implants, and unauthorized telemetry devices all transmit periodically. Fox Hunt on the known frequency of a suspected implant type (433.92 MHz for most consumer-grade bugs, 315 MHz for US market devices) will physically guide you to within a metre of the source.

**Covert navigation by haptic alone**  
The non-audible haptic alert means you can search for a transmitter in an occupied space — conference room, server room, lobby — without drawing attention. The pulse-rate gradient is strong enough to feel through clothing.

**Verifying antenna directionality**  
Point CYM in different directions while standing still. On a directional antenna, the RSSI and haptic response will peak when aimed at the transmitter — confirming both antenna directionality and rough bearing to the target.

### Field scenario

Post-assessment sweep of a data center. The client wants to know if there are any covert RF transmitters. You lock CYM onto 433.92 MHz in Fox Hunt mode, slip it in your jacket pocket, and walk the floor. Short buzzes. Far away. You walk toward the server rows. The pulses start coming faster. By the time you're halfway down row 14 it's nearly continuous in your hand. You stop. Look around. Behind a ventilation panel screwed to the back wall: a commercial GSM bug transmitting telemetry every 30 seconds. You found it by feel, in a room full of equipment, without ever looking at the screen.

---

## CC1101 Saved .sub Files

Browse and replay any `.sub` file saved on the SD card. Compatible with files captured directly on CYM or exported from a Flipper Zero.

### Research use cases

**Flipper Zero integration**  
CYM and Flipper Zero share the `.sub` file format exactly. Capture on Flipper in the field, copy the SD card to CYM, replay with CYM's higher-power CC1101 output. Or capture on CYM and analyse on Flipper.

**Evidence library**  
Maintain a library of captures organised by site/date on the SD card. Each file is human-readable text (pulse durations in µs) so it can be opened in any text editor for manual inspection.

---

## CC1101 Hardware Test

Verifies the CC1101 SPI communication and oscillator calibration. Expected: `PARTNUM=0x00 VERSION=0x14`.

Use this first when troubleshooting — if it fails, check DIP 1 and the FPC2 connector before attributing issues to software.

---

## CC1101 Jammer

> **Lab environments only.** Transmitting on ISM bands without authorization is illegal in most jurisdictions. Use only in shielded environments or in explicit authorized testing.

Sweeps across a configurable sub-GHz band using continuous 2-FSK modulated carrier with PRBS data — the widest-bandwidth noise mode the CC1101 supports. Useful in shielded lab settings to:

- Verify receiver sensitivity specs on your own hardware
- Test AGC behavior and overload recovery in your own radio designs
- Simulate interference conditions for protocol robustness testing
