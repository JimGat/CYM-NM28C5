# Infrared Research

> **Requires:** NM-RF-HAT with DIP 4 ON.  
> **Hardware:** TX — XL-504IRC-940 940 nm IR LED driven via AO3401A FET. RX — IRM-36381 38 kHz demodulator. Both share GPIO8 (TX) and GPIO9 (RX) via the RMT peripheral.  
> **File format:** Flipper Zero `.ir` — directly portable between CYM and Flipper Zero.

---

## Capture — Signal Recording

<!-- screenshot: ir_capture.png -->

Listens for any IR signal on the 38 kHz demodulator, records the raw mark/space pulse sequence, and saves to a named `.ir` file on the SD card under `/sdcard/lab/infrared/`.

**Naming flow:** After capture you pick an existing remote file or create a new one, then name the signal. The signal name is pre-filled with an auto-counter (`signal_0001`, `signal_0002`, …) that you can override.

### Research use cases

**IR remote control cloning**  
Physical security assessments often overlook IR-controlled devices: server room AC units, AV systems, projectors, smart TVs, and — increasingly — IR-controlled door locks and safe panels. Capture the "unlock" or "open" signal from a target remote and replay it at will.

**HVAC and building control systems**  
Enterprise HVAC controllers frequently use IR for zone configuration. Capturing the IR commands lets you document the full command set and identify whether any privileged commands (e.g., maintenance mode, factory reset) are accessible without authentication.

**Unknown protocol documentation**  
Not all IR devices use NEC or RC5. Capture the raw pulse train, import the `.ir` file into a text editor (it's plain text µs durations), and compare against protocol databases. Universal Radio Hacker can also import the pulse data for visual analysis.

**Capture for Flipper Zero**  
CYM and Flipper Zero share the `.ir` format exactly. Use CYM's larger antenna and higher TX power for long-range captures, then copy the SD card to a Flipper for portability.

---

## Replay — Signal Retransmission

<!-- screenshot: ir_replay.png -->

Browses saved `.ir` files by remote name, then lists individual signals. Tap a signal to retransmit it via the IR LED.

### Research use cases

**Proof-of-concept for IR-based access**  
After capturing an "unlock" command, walk back to the access point and replay it. If the device responds, you've demonstrated that physical security relies on an unauthenticated, easily-captured IR command — a finding that belongs in any physical pen test report.

**AV system and projector control**  
During a red team engagement, IR-controlling AV equipment in a conference room (cutting the display during a board meeting, muting microphones, displaying alternate content) is a high-impact physical action that many scenarios overlook.

**Regression testing for IR-controlled hardware**  
For hardware developers, a library of captured signals provides a reproducible test suite. Replay each command and measure the device response — more reliable than button presses during automated testing.

---

## Edit Files — Remote Library Management

<!-- screenshot: ir_edit.png -->

Browse, rename, and delete entries in your saved `.ir` remote library.

- **Remote list view:** all `.ir` files on the SD card — rename a file or delete it (with confirmation popup)
- **Signals view:** all named signals within a remote — rename or delete individual signals
- **Keyboard:** teal-bordered input with blinking cursor, matching the project-wide keyboard style

### Research use cases

**Assessment cleanup**  
After a physical assessment, remove client-specific captures before handing the device to the next engagement. The delete-with-confirmation flow prevents accidental loss while making cleanup quick.

**Library curation**  
Builds up a personal reference library over time: one `.ir` file per device type (hotel TV, brand X projector, enterprise AC unit), each with clearly named signals. Rename auto-generated signal names to meaningful ones (`power_on`, `unlock_door`, `factory_reset`) in the field.

---

## LED Remote — RGB Strip Controller

<!-- screenshot: led_rmt.png -->

28-button one-tap IR remote for NEC-protocol RGB LED strip controllers. 7-row × 4-column colour-coded grid. Library selector toggles between two button sets:

- **Custom** — 28 codes captured from a physical Submersable-style LED strip remote (all codes verified against hardware)
- **44-Key** — 28-button subset of the standard 44-key NEC RGB LED remote

### Research use cases

**IR controller fingerprinting**  
Many cheap RGB LED strip controllers share the same NEC address (0x00) but respond to slightly different command byte sets. The library selector lets you try both common code tables against an unknown controller to identify its variant without a physical remote.

**Home automation / IoT lab control**  
Control LED lighting in a lab environment directly from CYM without a separate remote — useful when running tests in the dark or when the physical remote is unavailable.
