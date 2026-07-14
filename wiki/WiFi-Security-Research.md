# WiFi Security Research

> CYM uses the ESP32-C5's native **WiFi 6 (802.11ax)** radio covering both **2.4 GHz and 5 GHz** bands simultaneously (`WIFI_BAND_MODE_AUTO`). MAC address: unique per device, visible in Settings.

---

## WiFi Scanner

<!-- screenshot: wifi_scanner.png -->

Passive active scan across all channels. Displays SSID, BSSID, RSSI, channel, and encryption type for every access point in range.

### Research use cases

**Network enumeration during physical assessment**  
Quick snapshot of every AP broadcasting in the environment. Identifies hidden SSIDs (shows `<hidden>` with the BSSID), rogue APs using corporate-looking names, and misconfigured open networks.

**Encryption audit**  
Filter the scan results for `OPEN` or `WEP` networks — legacy encryption that is trivially broken. A single-glance scan of a corporate lobby often surfaces guest networks still running WEP or open captive portals.

**Channel planning and interference**  
Identifies which channels are congested, which APs are on non-standard channels, and whether 2.4 GHz / 5 GHz co-channel interference is present. Useful pre-assessment for RF-heavy environments.

**BSSID enumeration for follow-on attacks**  
The BSSID list feeds directly into Deauth and Handshake Capture — select your target from the scan results.

---

## Deauthentication Attack

<!-- screenshot: deauth.png -->

Sends 802.11 deauthentication frames to a selected BSSID/client pair, forcing clients off the network. A **3-second haptic burst fires the moment the attack launches** — non-audible confirmation that the deauth stream started, useful when operating the device at arm's length or inside a bag.

### Research use cases

**Testing 802.11w — Protected Management Frames (PMF)**  
802.11w makes deauth frames unacceptable if they don't carry a valid MIC. A deauth attack against a PMF-enabled AP should have **no effect** — clients stay connected. This is the most direct way to verify that PMF is actually enforced on a network. If clients drop, PMF is either disabled or misconfigured.

**WPA2 handshake harvesting**  
Clients that reconnect after deauth will complete a 4-way handshake that CYM's Handshake Capture tool records. See [Handshake Capture](#handshake-capture) below.

**Client resilience testing**  
Some devices (IoT sensors, industrial controllers, POS terminals) reconnect insecurely or switch to a fallback network when deauthed. Testing this behavior in a controlled environment surfaces the risk before a real attacker does.

**Rogue AP detection baseline**  
Send a deauth burst to your own AP and observe which clients reconnect immediately vs. clients that switch to a rogue AP with a stronger signal. This reveals which clients are susceptible to evil twin attacks.

### Field scenario

Client claims their enterprise WiFi is protected by 802.11w. You select their BSSID, launch deauth, and feel the 3-second haptic blast confirm the attack started — your hand buzzes while you're watching their client devices on the other side of the room. Three devices drop connection immediately. PMF is either off or misconfigured on those clients. Two devices stay connected. Those two have it correctly enforced. One tap, one haptic confirmation, and you have a definitive per-device PMF audit in under 30 seconds.

---

## Handshake Capture

<!-- screenshot: handshake.png -->

Puts the radio into monitor/promiscuous mode on a selected channel and captures WPA2 EAPOL 4-way handshakes. Saved as `.pcap` (802.11 raw) and `.hccapx` (hashcat input) to `/sdcard/lab/handshakes/`.

### Research use cases

**Authorized password auditing**  
The `.hccapx` file can be fed directly to `hashcat -m 2500` or `aircrack-ng` to test the PSK against a wordlist or rule set. This is the standard method for verifying that a WPA2 PSK meets organizational password policy.

**PMKID capture (clientless)**  
Modern WPA2 routers expose the PMKID in the first EAPOL frame from the AP, allowing handshake capture without waiting for a client to connect. CYM captures this passively.

**WPA3 transition mode audit**  
Networks running WPA3-SAE + WPA2 in transition mode remain vulnerable to handshake capture against WPA2 clients. Capturing the handshake proves the transition mode represents a downgrade attack surface.

**Evidence collection**  
The `.pcap` format is readable by Wireshark for detailed frame-level inspection, timestamp verification, and chain-of-custody documentation during authorized assessments.

### Field scenario

Authorized password audit. The client wants to know if their WPA2 PSK meets policy. You select their AP, kick one client with a deauth burst, watch it reconnect over the next three seconds, and the handshake is captured. Fifteen seconds total. The `.hccapx` goes to hashcat before you've finished your coffee. The PSK is `CompanyName2023!`. It cracks in four minutes against a rule-based mutation of a common wordlist. The client's password policy said minimum 12 characters, uppercase, number, special character. Technically compliant. Practically broken. That nuance goes in the executive summary.

---

## Evil Twin / Captive Portal

<!-- screenshot: evil_twin.png -->

Starts a rogue AP with a configurable SSID and serves a captive portal (customizable HTML) to connecting clients. Logs submitted credentials to the SD card.

### Research use cases

**Phishing simulation in red team exercises**  
Deploy an evil twin matching a corporate guest SSID. Employees who connect and enter credentials to "re-authenticate" demonstrate susceptibility to credential harvesting attacks. This is one of the most common physical red team techniques.

**Testing device auto-connect behavior**  
Devices that automatically connect to any open network with a known SSID (a common IoT misconfiguration) will connect without user interaction. Listing them in the captive portal log proves the scope of the auto-connect vulnerability.

**Captive portal detection bypass research**  
Some devices send captive portal probes to known endpoints (e.g., `connectivitycheck.gstatic.com`). Hosting the evil twin lets you observe exactly which probe URLs a device uses and whether it validates TLS certificates — a common vector for MITM on IoT devices.

### Field scenario

Red team engagement, day two. You set up an evil twin in the parking lot matching the client's guest SSID. Over the next 90 minutes, eleven devices connect automatically — mostly contractor laptops that joined the guest network on a previous visit and stored the credentials. Three employees enter their domain credentials into the captive portal login page thinking they're re-authenticating to the real network. The log on your SD card has their usernames and passwords in plaintext. The client's guest network had no client isolation, no certificate-based authentication, and no user training about portal verification. All three findings make the report.

---

## ESP-NOW Scout

<!-- screenshot: espnow_scout.png -->

Passively detects **ESP-NOW** frames on a fixed or hopping channel. Logs source/destination MACs, RSSI, channel, timestamp, frame length, and OUI vendor hint to `/sdcard/lab/espnow/`.

### What it detects

ESP-NOW is Espressif's proprietary low-latency peer-to-peer WiFi protocol, operating as raw 802.11 vendor-specific action frames. It is widely used in:
- DIY IoT sensor networks (ESPHome, Tasmota, custom firmware)
- RC car/drone controllers
- Industrial sensor meshes
- Smart home button/switch arrays

### Research use cases

**IoT infrastructure discovery**  
ESP-NOW devices don't appear in a standard WiFi scan because they don't associate with an AP. The Scout is the only passive way to enumerate them. Identifies unreported IoT deployments during a facility assessment.

**Device tracking by MAC**  
ESP-NOW devices typically use a fixed MAC (the factory-assigned address). The Scout log timestamps every observed transmission, giving you a presence/activity timeline for each device.

**Channel analysis**  
ESP-NOW can operate on any 2.4 GHz or 5 GHz channel. Channel-hopping mode lets you find the channel(s) in use before locking in for deeper capture.

**Broadcast vs. unicast identification**  
Broadcast ESP-NOW frames (destination `FF:FF:FF:FF:FF:FF`) are unencrypted by spec. Unicast frames may carry an LMK-encrypted payload. The Scout distinguishes these and flags encrypted unicast sessions for follow-up.

### Field scenario

Warehouse audit. The client runs inventory sensors throughout the floor but can't account for all of them in their documentation. You open ESP-NOW Scout and start channel hopping. Within two minutes: 14 source MACs, all on ch 6, all from the same ESP32 OUI. Twelve match the documented sensors. Two don't — different MAC batch dates, not in the asset management system, never registered with IT. Both have been silently transmitting data in a protocol that doesn't appear in any WiFi scan for an unknown period of time. You found two ghost devices that standard network monitoring would never have seen.

---

## Chanalizer — Channel Utilisation Analyser

<!-- screenshot: chanalizer.png -->

Real-time per-channel utilisation display for 2.4 GHz and 5 GHz. Shows AP count, client activity, and signal density per channel with a colour-coded bar graph. Tap a channel to see the SSIDs active on it.

### Research use cases

**Pre-engagement RF survey**  
Before a wireless pen test, a 2-minute Chanalizer session shows channel saturation, which channels the target network is on, and which adjacent channels are clear. Informs attack planning (e.g., best channel to host an evil twin with the least interference).

**Rogue AP detection**  
An unexpected AP on a normally clear channel, or a sudden spike in channel utilisation, can indicate a rogue AP or an ongoing wireless attack by someone else in the environment.

**5 GHz coverage gap identification**  
5 GHz has significantly more non-overlapping channels. The Chanalizer reveals which 5 GHz channels are in use and which are idle — useful for identifying coverage gaps in a corporate wireless deployment.

### Field scenario

Pre-engagement WiFi survey for a penetration test. Two minutes with Chanalizer tells you that the client's corporate SSID lives on 2.4 GHz ch 6 — already saturated with three overlapping APs and a neighbour's network. Channel 11 is completely clear. You set your evil twin on ch 11 with a slightly stronger SSID broadcast and it becomes the cleanest signal in the building before you've opened a terminal window. Chanalizer didn't just show you the landscape — it handed you the best position in it.
