# CYM — Real World Use Cases

A single-page master reference of every field scenario across all CYM features. Each entry describes a realistic research or pen test situation and what CYM does in it. Ordered from most cinematic to most methodical.

> **Legal notice:** All scenarios described here involve authorized testing on networks, devices, and environments where explicit written permission was obtained. Unauthorized use of these techniques is illegal.

---

## BLE Cross-Location Device Correlation & Go Dark

You're doing a counter-surveillance assessment for a client who suspects they're being followed. No face, no plate, no name. Just a pattern — the same feeling of being watched at four completely unrelated locations over two weeks: a coffee shop downtown, a parking garage, a hardware store across town, a restaurant. You were there for the debrief at each one.

At every location you ran a passive BLE scan for ten minutes and saved the list. Four lists. Hundreds of devices in each — phones, laptops, store beacons, other customers' earbuds. A sea of MACs.

Here's the thing about modern phones: they rotate their BLE MAC address every ten to fifteen minutes for privacy. Across four independent scans days apart, a phone almost never appears in more than one list. But certain devices don't rotate. **AirTags. Tile trackers. Fitbits. Garmin watches. Galaxy Buds. Cheap BLE earbuds from Amazon.** Static factory MACs. They show up identically every single time.

You load all four scan files into the List Wizard and run the intersection. Out of hundreds of devices per scan, the common set collapses to nine MACs. Two are store fixture OUIs — coffee shop beacons, coincidentally present at two locations. Discarded. One is your client's own Fitbit. Two more resolve to a known tracking device OUI. Four are unresolved consumer electronics.

Those four unknown devices were in the same physical space as your client at four locations chosen at random over two weeks. That is not a coincidence.

You tap **Push to Lookout**. All four MACs land directly in the BT Lookout watchlist in one shot. Then you hit **Go Dark**. The screen goes black — not sleep, Blackout. The display is completely off. No glow through a shirt pocket. No reflection in a window. No bright rectangle for anyone to clock. CYM is invisible in your hand. Fully awake, fully silent. Just a warm rectangle in your jacket.

You sit down at a table near the entrance and order a coffee.

Eleven minutes later your jacket buzzes. One second on, half a second off. One second on, half a second off. One second on. Three beats. The BT Lookout pattern. You don't reach for the device. You don't look down. You lift your coffee and scan the room the way anyone would when they hear a door open.

A man in a grey jacket just sat down at the bar. He's looking at his phone. One of those four MACs walked through the door with him.

You set your coffee down and say, quietly, to your client across the table: "Don't turn around. We have a problem."

Four passive scans. A list intersection no human eye could perform across hundreds of devices. One tap to a live watchlist. A blacked-out screen that reveals nothing. A haptic alert felt through fabric before you made a single visible move. The tail never knew the net was already closing. They just walked into a room with a $20 board that had been waiting for them for eleven minutes.

---

## Sub-GHz Capture & Replay — Fixed-Code OOK

Physical assessment of a distribution warehouse. The client uses 433 MHz wireless door sensors and a keypad-armed alarm system. You open Band Scope on 433 MHz and watch the waterfall. Every time a forklift passes a dock sensor you see a spike — frequency confirmed in seconds. You hit Capture, walk past the dock door once, wait ten seconds. The `.sub` file lands on the SD card. You name it `dock_door_open`.

Two hours later you walk back to the dock door. No remote. No keyfob. No social engineering. You select the file, hit Replay, and the door opens. The alarm panel disarms. You just demonstrated that the entire perimeter security system runs on fixed-code OOK with zero replay protection, using a device that cost less than a cup of coffee. Critical finding.

---

## Sub-GHz Fox Hunt — RF Direction Finding by Haptic

Post-assessment sweep of a data center. The client wants to know if there are covert RF transmitters. You lock CYM onto 433.92 MHz in Fox Hunt mode, slip it in your jacket pocket, and walk the floor. Short buzzes — far away. You walk toward the server rows. The pulses come faster. By the time you're halfway down row 14 it's nearly continuous in your hand. You stop. Behind a ventilation panel screwed to the back wall: a commercial GSM bug transmitting telemetry every 30 seconds. Found by feel, in a room full of equipment, without ever looking at the screen.

---

## BT Locator — BLE Proximity Navigation

Same data center. BLE Observer flagged an unknown MAC advertising every two seconds — too regular for a phone, unknown OUI. You lock it into BT Locator and slip CYM into your bag. The motor is barely breathing as you walk the floor. Near the back of row 14 the pulses start coming faster. Stronger. By the time you're at rack 22 it's running full strength. You look under the cable management arm. Zip-tied to the rack frame: an ESP32 dev board on a USB battery pack, blinking its status LED. Found entirely by feel.

---

## BLE Honeypot — Who Is Hunting Me?

Hospital BLE assessment. You spend five minutes running GATT Walker on a bedside infusion pump to capture its advertisement profile. CYM clones it — same device name, same service UUIDs, same manufacturer data — and starts broadcasting as a connectable device. You set it on a supply cart and walk away. Four minutes later something connects. Not a nurse's tablet. A background process on a laptop three rooms over that was silently scanning for connectable infusion pump profiles. It immediately tried to read the drug dosage characteristic without any pairing request, no authentication, no handshake. The hospital had no idea. The Honeypot found it without you actively probing anything — it just waited, and the threat revealed itself.

---

## GATT Clone — Device Impersonation Without the Hardware

You're auditing the companion app for a smart lock installed on the client's front door — you can't take it into the lab. You run GATT Walker on it for two minutes in the field. Back at your desk, CYM serves that exact GATT profile to any connecting app. You install the lock's companion app on a test device, connect it to CYM, and watch every byte it sends. On first connection the app transmits the unlock PIN in plaintext to a writable characteristic. No crypto, no auth challenge, no certificate pinning. The real lock stayed on the door. The clone gave you everything you needed from fifty miles away.

---

## BT Lookout — Silent Watchdog

Red team exercise. You load the OUI prefix for the client's security laptops and MDM-managed iPhones into BT Lookout, hit Go Dark so the screen goes black, and drop CYM into your jacket pocket. You sit in the lobby with a coffee and a newspaper. Eleven minutes later your jacket buzzes — one, pause, two, pause, three. Security just walked past you in the hallway behind you. You don't look up, don't change your posture, don't reach for anything. You set the coffee down and turn to a new page. You knew they were coming before they rounded the corner.

---

## GATT Walker — Undocumented Write Characteristic

IoT assessment, warehouse temperature sensors. Nothing in the datasheet mentions remote configuration. You connect GATT Walker and let it run for two minutes. Buried in the vendor-specific service tree: a writable characteristic labelled `0xFF03` — not in any documentation. You write a test value to it. The sensor immediately changes its reporting interval from 60 seconds to 1 second, flooding the backend. That undocumented write could crash the entire telemetry pipeline or mask legitimate environmental readings. Critical finding.

---

## nRF24 Sniffer — Wireless Keyboard Dongle Research

Conference room, half the keyboards are wireless USB dongle types. You open nRF24 Channel Scan and watch channels 25, 50, and 74 light up — the classic nRF24 dongle cluster. You lock the Sniffer to ch 50. Thirty seconds later someone types their laptop password. The packet log on your SD card has the keystroke data. This is the published MouseJack attack class — CYM gives you the capture layer. The vulnerability has been public since 2016. Most organizations never pushed the dongle firmware update.

---

## NFC Clone & Emulate — Access Control PoC

Physical pen test. The receptionist's desk has visitor badges in a tray. You ask to see one "to check compatibility." CYM reads the UID in under a second while you're holding it. Badge goes back. Thirty minutes later, in your car: you write the UID to a $0.10 blank NFC tag. Walk back in and tap the sticker to the server room reader. Door opens. The access control system checked only the UID. MIFARE Classic deployed with no sector-level crypto authentication. You run it a third time using CYM's live Card Emulation just to document all three attack vectors for the report. Three demonstrations, one morning, ten cents in materials.

---

## WPA2 Handshake Capture — Password Auditing

Authorized password audit. You select the client's AP, kick one client with a deauth burst, catch the 4-way handshake on reconnect. Fifteen seconds total. The `.hccapx` goes to hashcat before you've finished your coffee. The PSK is `CompanyName2023!`. Cracks in four minutes against a rule-based wordlist mutation. Technically meets the policy (12 chars, uppercase, number, special character). Practically broken in under five minutes. The difference between "compliant" and "secure" is in the executive summary.

---

## Deauth + PMF Testing

Client claims 802.11w is enabled everywhere. You select their BSSID, launch deauth, feel the 3-second haptic confirmation in your hand while watching their client devices across the room. Three devices drop. Two stay connected. PMF is misconfigured on those three clients. One tap, one haptic, definitive per-device PMF audit in under 30 seconds.

---

## Evil Twin / Captive Portal — Credential Harvesting

Red team, day two. You set up an evil twin in the parking lot matching the client's guest SSID. Over 90 minutes, eleven devices connect automatically — contractor laptops that saved the guest credentials from a previous visit. Three employees enter domain credentials into the portal thinking they're re-authenticating. Their usernames and passwords are on your SD card in plaintext. No certificate auth, no client isolation, no user training on portal verification. All three findings in the report.

---

## ESP-NOW Scout — Ghost Device Discovery

Warehouse audit. The client can't account for all their inventory sensors. You open ESP-NOW Scout and start channel hopping. Two minutes later: 14 source MACs, all on ch 6, all from the same ESP32 OUI. Twelve match documented sensors. Two don't — different MAC batch dates, not in any asset register. Both have been silently transmitting in a protocol invisible to standard WiFi scanning for an unknown period. Two ghost devices, found in two minutes, using a protocol most network security tools can't see.

---

## Z-Wave Scout — Undocumented Smart Building Infrastructure

Corporate office assessment. Nobody mentioned Z-Wave in scope. You run Z-Wave Scout for ten minutes while walking the building. The log comes back with seven unique Home IDs and dozens of Node IDs — thermostats, motorized blinds, smart lighting, and a Z-Wave lock on the executive suite. The client's IT team has zero visibility into any of it. A building management contractor installed it three years ago and never told anyone. Found passively, without joining any mesh, without sending a single command frame.

---

## Drone Detector — Unauthorized Airspace Monitoring

Outdoor event security. You set CYM on the production table and let Drone Detector run. Twenty minutes in: three drones detected. Two match the authorized fleet — correct operator IDs, GPS inside the approved corridor. The third doesn't. Its Remote ID shows an operator 200 metres outside the perimeter fence and a flight path directly over the stage. No app, no network, no subscription. CYM decoded it from a BLE advertisement. Security has a grid reference for the operator before the song ends.

---

## nRF24 Fox Hunt — 2.4 GHz Direction Finding

Same data center sweep, unknown MAC on 2.4 GHz instead of sub-GHz. Channel Scan shows anomalous carrier on ch 74. Fox Hunt locked, CYM pocketed. The motor goes from slow taps to a rapid hammering as you approach rack 22. Behind the cable tray: same setup, different radio — an nRF24-based device on a channel nobody assigned. Found by feel, without a screen.

---

## BLE Spam — MDM Policy Validation

Pre-conference MDM audit. You start BLE Spam in the break room. Policy says managed iOS devices must suppress pairing prompts from unauthorized accessories. Three attendee phones start showing pairing popups. All three belong to contractors on personal devices, outside MDM enrollment. Gap confirmed and documented before the morning session starts.

---

## Band Scope → Capture → Replay (Full Chain)

You enter a target building knowing it uses sub-GHz wireless security but nothing else. Band Scope shows you what's transmitting and at what frequency. Frequency Scan narrows the channel. Capture records the signal in one physical pass. Replay retransmits it on demand. The entire workflow — discovery to proof of concept — runs on one device, fits in a jacket pocket, saves every step to a standard file format, and requires no laptop, no external tools, and no protocol knowledge about the target system. The physical security audit chain in four taps.
