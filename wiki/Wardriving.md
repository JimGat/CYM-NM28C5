# Wardriving & Geolocation

> CYM integrates passive WiFi scanning, BLE enumeration, and GPS logging into a single wardriving pipeline with direct export to **WiGLE** and **WDG Wars**.

---

## How It Works

<!-- screenshot: wardrive_screen.png -->

1. Attach a GPS module to the LP-UART header (TX→GPIO5, RX→GPIO4)
2. Start Wardrive from the main menu
3. CYM scans all 2.4 GHz + 5 GHz WiFi channels and runs BLE advertising capture simultaneously (hardware coexistence — both radios active)
4. Every detected network/device is timestamped, geotagged, and written to `/sdcard/lab/wardrive/`
5. Upload directly to WiGLE or WDG Wars over WiFi from the Settings → Data Transfer screen

### What gets logged

| Type | Fields |
|------|--------|
| WiFi AP | SSID, BSSID, RSSI, channel, band, encryption, lat, lon, altitude, accuracy, timestamp |
| BLE device | MAC, address type, RSSI, name, manufacturer data, lat, lon, timestamp |

Output format: **WiGLE CSV 1.6** for WiFi; WiGLE-compatible CSV for BLE.

---

## Research Use Cases

**Network mapping during mobile assessments**  
Drive or walk the perimeter of a facility while wardrive runs. The resulting map shows every AP broadcasting from inside the building, including networks on channels you wouldn't normally find with a static scan. The GPS track overlaid on the data shows exactly where each AP's signal reaches — often extending further into parking lots and public streets than the organization realizes.

**Rogue AP geolocation**  
If a rogue AP is broadcasting an SSID matching your client's corporate network, the wardrive log gives you its GPS position accurate to a few metres. Cross-referencing the rogue's BSSID against the WiGLE database can reveal when it first appeared and who else has seen it.

**BSSID / MAC geolocation for OSINT**  
BSSIDs uploaded to WiGLE are cross-referenced against the global database. An AP's historical GPS positions reveal where a device has been — useful in investigations where a WiFi-enabled device (laptop, router) has been moved. This technique is used in legal and forensics contexts.

**Wardriving for RF coverage evidence**  
Organizations sometimes dispute whether their wireless signals extend outside their premises (relevant for regulatory compliance or lease agreements). A georeferenced wardrive proves signal presence at specific coordinates with RSSI measurements.

**BLE device tracking during mobile survey**  
BLE devices with static MACs appear repeatedly in the log as you move. Clustering observations by MAC gives the physical location of fixed BLE beacons, asset tags, and IoT sensors — building a complete picture of the wireless estate.

**Community contributions**  
WiGLE is the largest public database of wireless networks. Contributing wardrive data helps researchers studying urban RF density, ISP coverage gaps, and wireless protocol adoption. WDG Wars adds a competitive/gamification layer for community engagement.

---

## GPS Module Integration

CYM auto-detects NMEA sentences on the LP-UART RX pin (GPIO4) at 9600 baud. Any USB or hardware UART GPS module that outputs standard NMEA (`$GPRMC`, `$GPGGA`) works.

The GPS Info screen (Settings → GPS Info) shows:
- Fix status (No module / No fix / 2D / 3D)
- Satellite count
- Current lat/lon/altitude
- Speed and heading

Wardrive data is only geotagged when a valid 3D fix is present. Records without fix are still logged with a `NO_FIX` marker and excluded from the WiGLE upload.
