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

### Field scenario

You arrive at a hospital for a medical device security assessment. Before touching a single device, you open BLE Observer and let it run for ten minutes in the waiting room. By the time you sit down with the IT team, you already have a list of 47 advertising devices — including three infusion pumps in a nearby ward, two glucometers, and a BLE-enabled nurse call system that nobody mentioned in the asset register. Two of the pumps are advertising as connectable. That becomes the first item on the day's agenda.

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

### Field scenario

You're doing an IoT assessment for a client whose warehouse uses BLE-enabled industrial temperature sensors. Nothing in the datasheet mentions remote configuration. You connect GATT Walker and let it run for two minutes. The JSON that lands on your SD card tells a different story: buried inside the vendor-specific service tree is a writable characteristic labelled `0xFF03` — not documented anywhere. You write a test value to it. The sensor immediately changes its reporting interval from 60 seconds to 1 second, flooding the backend. That one undocumented write characteristic could crash the entire telemetry pipeline or mask legitimate environmental readings. It goes straight into the report as a critical finding.

---

## BT Lookout — Persistent Device Monitor

<!-- screenshot: bt_lookout.png -->

Continuous BLE scanner that compares every observed advertisement against a **watchlist** of target MACs and OUI prefixes. On each match it logs a timestamped entry to `/sdcard/lab/bt_lookout/watchlist.csv` and fires a **haptic alert: 3 × 1-second vibration bursts with 500 ms gaps**. The alert is non-audible — felt in a pocket or on a surface without drawing attention in a quiet environment.

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

**Covert alerting during walk-throughs**  
Because the alert is haptic-only, you get a clear "target detected" signal in your hand while maintaining a natural appearance — no screen to glance at, no audible ping. Walk a facility at a normal pace; the burst pattern is distinctive enough to feel through a jacket pocket.

### Field scenario

Red team exercise. You've been told the client's security team will try to identify you during the engagement. You load the OUI prefix for their brand of security laptops and their MDM-managed iPhone fleet into BT Lookout, hit Go Dark so the screen goes completely black, and drop CYM into your jacket pocket. You sit down in the lobby with a coffee and a newspaper. Eleven minutes later your jacket buzzes — one, pause, two, pause, three. Security just walked past you in the hallway behind you. You don't reach for your phone, don't look up, don't change your posture. You set your coffee down and turn to a new page. You knew they were coming before they rounded the corner.

---

## BT Locator — Proximity Tracking with Variable Haptic

<!-- screenshot: bt_locator.png -->

Locks onto a selected BLE device's MAC and tracks its signal strength in real time. Unlike BT Lookout's binary match/no-match, BT Locator uses **variable-intensity haptic feedback** tied directly to RSSI — the motor spins faster and stronger as you get closer to the target.

**Haptic scaling:** Pulses fire every 500 ms. Motor intensity is computed from RSSI: `strength = 10 + (RSSI + 69) × 90 / 29`, clamped to 10–100 %. Silent below −69 dBm (device out of useful range). At −40 dBm and above the motor runs at full strength. Both the pulse feel and cadence change with distance — experienced users can navigate by touch alone.

### Research use cases

**Physical locating of a known BLE device**  
Once you have a target MAC (from a prior BLE Observer scan or GATT Walker session), BT Locator guides you to it by feel. Walk toward stronger feedback. Useful for locating:
- Hidden BLE beacons or trackers in a facility
- An asset tag attached to a specific piece of equipment
- A rogue BLE device planted during a prior access

**Covert search during physical assessment**  
Keep CYM in a pocket and navigate to a target device without looking at the screen. The haptic intensity gradient gives you directional guidance through walls and furniture — you'll feel the peak as you pass through the strongest-signal zone.

**Beacon placement validation**  
After deploying your own BLE beacons, walk the coverage area and use BT Locator to verify that RSSI falls off at the expected rate. Sharp drop-offs indicate RF obstructions; unusually long range indicates antenna misplacement or excessive TX power.

### Field scenario

Post-assessment sweep of a data center. The client wants to know if there are any unauthorized wireless devices. BLE Observer flagged an unknown MAC during the initial scan — unknown OUI, advertising every two seconds, slightly too regular to be a phone. You lock it into BT Locator and slip CYM into your bag. The motor is barely breathing. You walk the floor. Near the back of a row of racks the pulses start coming faster. Stronger. By the time you're standing in front of rack 14 it's running full strength every half second. You look underneath the cable management arm. Zip-tied to the back of the rack frame: a small ESP32 dev board on a USB battery pack, blinking its status LED once every two seconds. You found it without looking at a screen once.

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

### Field scenario

Outdoor event security assessment. Your client wants to know if unauthorized drones are operating over the venue. You set CYM on the production table and let Drone Detector run through the show. Within the first 20 minutes: three drones detected, all broadcasting Remote ID. Two match the authorized fleet — correct operator IDs, GPS positions inside the approved flight corridor. The third doesn't. Its Remote ID shows an operator location 200 metres outside the perimeter fence and a flight path arcing directly over the stage during the headliner's set. No app, no subscription, no network connection. CYM decoded it off a BLE advertisement. Security has a grid reference for the operator before the song ends.

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

### Field scenario

Hospital BLE security assessment. You spend five minutes running GATT Walker on a bedside infusion pump to capture its full advertisement profile. CYM clones it — same device name, same service UUIDs, same manufacturer data — and starts broadcasting as a connectable device. You set it on a supply cart and walk away to interview the IT team. Four minutes later something connects to the Honeypot. Not a nurse's tablet. Not the companion app running on an authorized device. A background process on a laptop three rooms over that was silently scanning for connectable infusion pump profiles. It immediately tried to read the drug dosage characteristic without any pairing request, no authentication, no handshake. The hospital had no idea that laptop had a background process doing that. The Honeypot found it without you actively probing anything — it just waited, and the threat revealed itself.

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

### Field scenario

You're auditing the companion app for a smart lock. The lock is installed on the client's front door — you can't take it into the lab. You run GATT Walker on it for two minutes in the field, capturing the full service tree to a JSON file on the SD card. Back at your desk, CYM serves that exact GATT profile to any connecting app. You install the lock's companion app on a test device, connect it to CYM instead of the real lock, and watch every byte it sends. On first connection the app transmits the unlock PIN in plaintext to a writable characteristic. No crypto, no auth challenge, no certificate pinning. The real lock stayed on the door. The clone gave you everything you needed from a desk fifty miles away.

---

## BLE List Analytics — Cross-Location Device Correlation & Go Dark

<!-- screenshot: ble_list_wizard.png -->

Load up to **four saved BLE scan lists** and find devices that appear across multiple scans — the intersection of who was present at multiple locations. Results can be pushed directly to BT Lookout as a live watchlist in one tap. Combined with **Go Dark** (display off, device fully active), the entire workflow runs covertly with no visible screen.

### Research use cases

**Cross-location device correlation**  
Scan BLE at each location where a subject or incident of interest was present. Devices that appear in all four lists were physically co-located with the subject every time. Modern phones rotate their MAC every 10–15 minutes and almost never survive a cross-scan intersection. Static-MAC devices — AirTags, Fitbits, Tile trackers, Garmin watches, Galaxy Buds, cheap BLE earbuds — appear identically every time. The intersection filter separates the signal from the noise automatically.

**Rogue tracker detection**  
Scan your own environment at multiple points during the day. Any device that persists across all four scans and resolves to a tracking device OUI is a candidate for an unwanted tracker attached to your vehicle, bag, or equipment.

**Authorized personnel tracking**  
In authorized insider-threat scenarios, four scans at four locations where a subject was present narrows hundreds of BLE devices down to the handful of personal devices that never leave the subject's possession.

### Field scenario

You're doing a counter-surveillance assessment for a client who suspects they're being followed. You don't have a face, a plate, or a name. What you have is a pattern — the same feeling of being watched at four completely unrelated locations over two weeks: a coffee shop downtown, a parking garage near their office, a hardware store across town, and a restaurant they visited once. You were there for the debrief at each one. At every location you ran a passive BLE scan for ten minutes and saved the list. Four lists. Hundreds of devices in each — phones, laptops, store beacons, other customers' earbuds. A sea of MACs.

Here's the thing about modern phones: they rotate their BLE MAC address every ten to fifteen minutes for privacy. Across four independent scans days apart, a phone almost never appears in more than one list. But certain devices don't rotate. **AirTags. Tile trackers. Fitbits. Garmin watches. Galaxy Buds. Cheap BLE earbuds from Amazon.** Static factory MACs. They show up identically every single time.

You load all four scan files into the List Wizard and run the intersection. Out of hundreds of devices per scan, the common set collapses to nine MACs. Two resolve to store fixture OUIs — the coffee shop's in-store beacons, coincidentally present at two locations. You discard them. One is your client's own Fitbit. Two more resolve to a known tracking device OUI. Four are unresolved consumer electronics.

Those four unknown devices were in the same physical space as your client at four locations chosen at random over two weeks. That is not a coincidence.

You tap **Push to Lookout**. All four MACs land directly in the BT Lookout watchlist in one shot. Then you hit **Go Dark**. The screen goes black — not sleep, Blackout. The display is completely off. No glow through a shirt pocket. No reflection in a window. No bright rectangle for anyone to clock. CYM is invisible in your hand. It is still scanning. Every advertisement packet in the air is still being checked against those four MACs in real time. Fully awake, fully silent — light, sound, nothing. Just a warm rectangle in your jacket.

You sit down at a table near the entrance and order a coffee.

Eleven minutes later your jacket buzzes. One second on, half a second off. One second on, half a second off. One second on. Three beats. The BT Lookout pattern. You don't reach for the device. You don't look down. You lift your coffee and scan the room with your eyes the way anyone would when they hear a door open.

A man in a grey jacket just sat down at the bar. He's looking at his phone. One of those four MACs walked through the door with him.

You set your coffee down and say, quietly, to your client across the table: "Don't turn around. We have a problem."

That is the full loop. Four passive scans. A list intersection that no human eye could perform across hundreds of devices. A one-tap push to a real-time watchlist. A blacked-out screen that reveals nothing. And a haptic alert felt through fabric in a crowded room before you made a single visible move. The tail never knew the net was already closing. They just walked into a room with a $20 board that had been waiting for them for eleven minutes.

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

### Field scenario

You're validating an organization's MDM policy before a large conference. Policy says all managed iOS devices must suppress pairing prompts from unauthorized accessories. You start BLE Spam in the break room before the morning session. If any attendee's phone starts showing pairing popups, that device either isn't enrolled in MDM or the policy isn't enforced correctly. You find three devices popping. All three belong to contractors using personal phones. MDM gap confirmed, documented, and reported before lunch.
