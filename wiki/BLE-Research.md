# BLE & Bluetooth Research

> CYM uses the ESP32-C5's **Bluetooth 5** radio with NimBLE stack. In Wardrive mode, WiFi + BLE run simultaneously via hardware coexistence (`CONFIG_ESP_COEX_SW_COEXIST_ENABLE`). On other screens, switching between WiFi and BLE stops the previous radio first.

---

## BLE Observer — Passive Device Enumeration

<!-- screenshot: ble_observer.png -->

Continuous passive BLE scan. Logs every advertisement packet: MAC, address type (public/random), RSSI, advertisement type (connectable/non-connectable/scannable), raw payload, and decoded common fields (name, service UUIDs, manufacturer data, TX power).

### Research use cases

**Device discovery in target environments**  
Passive BLE scanning discovers every advertising device in range without transmitting. A 10-second scan in a corporate office, hospital, or retail environment typically surfaces:
- Wireless keyboards and mice (often nRF24 dongles or BLE HID)
- BLE beacons (iBeacon, Eddystone)
- Medical devices (glucometers, infusion pumps, wearables)
- Smart locks and access control readers
- POS terminals with BLE interfaces
- Industrial sensors

**OUI-based vendor identification**  
CYM resolves the manufacturer OUI from every public MAC address. Unknown vendors, Chinese ODM MACs on unexpected device types, or consumer-grade hardware in sensitive environments are all immediately visible.

**Tracking window analysis**  
Devices using static BLE MACs (most IoT, many medical) appear in every scan at the same address. Devices using random resolvable addresses (modern phones) cycle their MAC every 10–15 minutes. Observing rotation intervals lets you characterize the privacy posture of a device fleet.

**Connectable vs. non-connectable inventory**  
Connectable advertisements (`ADV_IND`) mean the device will accept a GATT connection — a significant attack surface. Non-connectable beacons (`ADV_NONCONN_IND`) are information-only. CYM flags connectable devices so you can prioritise GATT Walker sessions.

---

## GATT Walker — Interactive GATT Inspector

<!-- screenshot: gatt_walker.png -->

Connects to a selected BLE device and **sequentially walks every service, characteristic, and descriptor**. For each characteristic it reads the value (if readable), notes properties (read/write/notify/indicate), decodes the value as UTF-8 ASCII where possible, and identifies it by name from the Bluetooth SIG assigned numbers list.

Output is saved as structured JSON to `/sdcard/lab/gatt/` with:
- Service and characteristic UUIDs + SIG-assigned names
- Properties string (`read | write | notify | indicate | …`)
- Raw value (hex) + ASCII interpretation
- OUI-resolved manufacturer name
- GPS coordinates if GPS module is attached (geotags the assessment)
- FNV-32 fingerprint of the full GATT map (for device-type deduplication)

### Research use cases

**IoT device GATT surface assessment**  
Most BLE IoT devices expose more than they intend to over GATT. Walk the full service tree before reading the datasheet — undocumented characteristics (especially writable ones on vendor-specific UUIDs) are common and often control firmware update mode, factory reset, or configuration parameters.

**Authentication bypass detection**  
Many BLE devices rely entirely on pairing for security but leave characteristics readable or writable without authentication. GATT Walker connects without pairing by default — any characteristic that returns a value or accepts a write without requiring bonding is potentially accessible to any BLE-capable device in range.

**BLE HID device analysis**  
BLE keyboards, mice, and barcode scanners expose HID Report descriptors over GATT. Walking these reveals the exact HID report format, button mapping, and battery service — useful when reverse-engineering a proprietary wireless peripheral.

**Firmware update service fingerprinting**  
OTA DFU services (Nordic DFU `0x0001`, TI OAD, custom vendor UUIDs) appear in the GATT tree. Identifying which DFU service a device uses determines the attack surface for firmware manipulation research.

**Device fingerprinting database**  
The FNV-32 fingerprint of a GATT map is stable across devices of the same firmware version. Run GATT Walker across multiple units of the same device and compare fingerprints to confirm firmware consistency — or detect that a "same model" device has unexpected services enabled.

---

## BT Lookout — Persistent Device Monitor

<!-- screenshot: bt_lookout.png -->

Continuous BLE scanner that compares every observed advertisement against a **watchlist** of target MACs and OUI prefixes. Triggers a haptic alert (`3 × 1 s vibration bursts`) and logs a timestamped entry to `/sdcard/lab/bt_lookout/watchlist.csv` on each match.

### Watchlist matching
- **Full MAC** — exact 6-byte match (identifies a specific known device)
- **OUI prefix** — 3-byte match (identifies any device from a specific manufacturer)

### Research use cases

**Rogue device detection**  
Load your target organization's OUI prefixes (e.g., your fleet of Apple, Zebra, or Honeywell devices). Any device from those manufacturers that appears in an unexpected location triggers an alert. Alternatively, load the OUI of a known attacker device (rubber ducky dongle, Flipper Zero Bluetooth adapter) to detect its presence.

**Asset tracking during physical assessment**  
Tag specific MAC addresses you want to follow. Walk the facility; CYM alerts you whenever a target device is in range, building a presence map of where the device appears throughout the day.

**Detecting wireless implants**  
After a physical intrusion assessment, run BT Lookout against a list of known implant OUIs (common BLE microcontrollers used in hardware implants). Alerts during the post-assessment sweep indicate devices that shouldn't be there.

**Personnel monitoring (authorized)**  
In authorized insider-threat simulations, load the BLE MAC of a specific person's phone or wearable. The CSV log provides a timestamped movement record.

---

## Drone Detector

<!-- screenshot: drone_detector.png -->

Passive BLE scanner tuned to decode **drone Remote ID** (RID) advertisements per ASTM F3411 / ASD-STAN prEN4709-002. Displays operator ID, drone ID, position, altitude, velocity, and emergency status from advertising drones.

### Research use cases

**Detecting unauthorized drones**  
Most commercial drones (DJI, Autel, and others) broadcast Remote ID as a mandatory BLE advertisement. CYM decodes this in real time — no app, no network connection required. Run it during an outdoor event, facility perimeter survey, or critical infrastructure inspection.

**Remote ID compliance verification**  
Verify that drones operating in your airspace are broadcasting compliant Remote ID packets with valid operator credentials. Non-compliant or spoofed RID packets (missing operator ID, static position, obviously false altitude) appear immediately.

**Drone operator location estimate**  
Remote ID includes operator GPS coordinates. If the drone is within BLE range (~100 m line of sight), the operator location field gives you an approximate position of the person flying it.

**Fleet validation**  
For organizations operating their own drone fleets, run the Drone Detector to confirm every drone is broadcasting its correct ID and that no unauthorized drones are mixed into the formation.

---

## BLE Honeypot — Connectable Device Impersonation

<!-- screenshot: ble_honeypot.png -->

Takes the advertisement profile captured by GATT Walker (device name, service UUIDs, manufacturer data, TX power) and re-broadcasts it from CYM as a connectable advertisement. Any device or app that connects is logged — MAC, address type, timestamp, and every GATT operation it performs (reads, writes, subscriptions).

### Research use cases

**Discovering hidden scanners and seekers**  
Most BLE attack-surface analysis focuses on what a target device advertises. The Honeypot flips the question: *who is actively looking for this device type?* Place CYM near a target environment impersonating a known device (a medical monitor, an industrial sensor, a POS terminal peripheral) and watch what connects. Background apps, rogue scanners, and unauthorized companion apps reveal themselves without any active probing on your part.

**Client-side trust assumption testing**  
Many BLE companion apps connect to any device that matches a target name or service UUID without verifying the device identity beyond the advertisement. The Honeypot confirms this by accepting connections and logging whether the connecting app sends credentials, commands, or sensitive data before any authentication step. This is a high-value finding in mobile app BLE security assessments.

**Post-assessment rogue device detection**  
After a red team engagement, leave the Honeypot running impersonating your own implant's BLE profile. If the client's blue team has deployed BLE monitoring, their detection system should alert — this validates whether their defensive tooling actually catches connectable rogue BLE devices.

**Mapping the attack surface of a target device type**  
Clone a device you're researching (e.g., a smart lock or glucose monitor) and observe what the manufacturer's companion app sends on first connection, pairing request, and subsequent reconnect. The log gives you the full client-side command sequence without needing a second physical unit.

---

## GATT Clone — Full Profile Impersonation

<!-- screenshot: ble_gatt_clone.png -->

After GATT Walker maps a real device, CYM can serve that device's **complete GATT profile** to any connecting client — identical service UUIDs, characteristic UUIDs, properties, and captured values. Connecting apps see no difference from the original device.

### Research use cases

**Reproducing device behavior without physical hardware**  
Once a GATT map is captured, you can leave the original device behind and continue assessment work with CYM standing in as the target. Useful when physical access to the device is limited (time-sensitive, locked enclosure, single unit in production use).

**Client app security assessment**  
Connect your target mobile app to a GATT Clone and observe its full interaction sequence: which characteristics it reads, which it writes, what values it sends, and whether it validates response data. Without a real device, the app behaves identically — but now every byte is under your control and everything is logged.

**Authentication bypass research**  
A GATT Clone that serves expected characteristic values can bypass basic "is this the right device" checks in companion apps that don't perform cryptographic pairing verification. If the app accepts the clone as a legitimate device, no pairing was cryptographically enforced.

**Regression and compatibility testing**  
For developers, clone a known-good device GATT profile and use it as a stable test fixture. Any client app change that breaks against the clone breaks against the real device too — without needing the hardware on the bench.

---

## BLE Spam — Advertisement Flood Testing

<!-- screenshot: ble_spam.png -->

Transmits a high-rate stream of crafted BLE advertisements mimicking Apple Nearby devices, Google Fast Pair, Samsung Pairing notifications, and other proximity protocols. Supports randomized MACs per packet.

> **Scope:** Resilience testing only. Intended to verify how target OS/device firmware handles unexpected advertisement floods — notification fatigue, UI freezes, battery drain under scan load.

### Research use cases

**Notification fatigue testing**  
Apple devices running iOS show pairing prompts for nearby accessory advertisements. Test how your organization's managed iOS fleet handles a stream of these — MDM-managed devices should suppress them, unmanaged devices surface the attack vector.

**BLE stack robustness**  
Some embedded BLE stacks (IoT sensors, medical devices, industrial controllers) have documented vulnerabilities in their advertisement processing path. Flood testing with varied payload lengths and advertisement types is a standard first step in BLE fuzzing.

**Scanner performance under load**  
Verify that your own BLE monitoring infrastructure (SIEM sensors, asset tracking gateways) handles high-density advertisement environments without dropping packets or crashing.
