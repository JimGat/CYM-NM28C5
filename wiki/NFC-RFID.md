# NFC & RFID Research (PN532)

> **Requires:** NM-RF-HAT with DIP 3 ON.  
> **Hardware:** PN532 (I2C mode, fixed by PCB resistors). Supports ISO14443A, ISO14443B, ISO18092. Firmware: IC=0x32, FW=1.6.  
> **Range note:** The NM-RF-HAT antenna has shorter read range than a dedicated PN532 breakout board. Cards may need to nearly touch the antenna for reliable reads.

---

## Scan & Read — Card Enumeration

<!-- screenshot: rfid_scan.png -->

Continuously polls the NFC field for cards. On detection:
- Identifies card type (NTAG213/215/216, MIFARE Ultralight, MIFARE Classic)
- Reads the UID
- For NTAG/Ultralight: reads all pages and decodes any NDEF TLV records (URI, text)
- Displays raw page data in hex
- Logs to `/sdcard/lab/rfid/cards/`

### Research use cases

**Access control card enumeration**  
The most common contactless access control cards in use today are MIFARE Classic (13.56 MHz, ISO14443A). CYM reads and logs the UID of every card it sees. UIDs are typically static and used as the sole identifier by access control panels — the critical finding is whether the system validates anything beyond UID presence.

**NFC tag content auditing**  
NTAG213/215/216 tags are ubiquitous: NFC product authentication stickers, marketing tags, asset labels, conference badges. The Scan & Read screen decodes the NDEF payload — revealing the URI or text written to the tag. Common findings: staging URLs still active on production tags, internal URLs exposed on marketing materials, writable tags that should be locked.

**Card inventory during physical assessment**  
Scan every access card and badge presented during a social engineering exercise. Log the UID and card type for each. Compare against the expected card type (many organizations unknowingly use MIFARE Classic when their policy specifies DESFire EV1).

**NDEF data extraction**  
Smart posters and tap-to-pay loyalty cards often store URIs pointing to backend systems. Read the NDEF payload to identify backend URLs, deep links, and app store targets — these sometimes point to staging environments or reveal the app bundle ID.

---

## Clone / Write — Credential Duplication

<!-- screenshot: rfid_clone.png -->

Reads a source NTAG/Ultralight card completely (all pages), then writes the identical page-by-page content to a blank target card of the same type.

### Research use cases

**Access control vulnerability demonstration**  
MIFARE Classic (and many Ultralight/NTAG deployments) are vulnerable to UID cloning because the access control panel uses only the UID for authentication. Clone a card UID onto a blank writable tag (e.g., a $0.10 NTAG213) and present it to the reader. If the door opens, you've demonstrated the vulnerability to the client in 60 seconds — no crypto attack required.

**Backup and restore for authorized testing**  
Before writing test data to a production NFC tag, clone it. You have a bit-exact backup to restore from if the test corrupts the tag.

**Credential mobility testing**  
Test whether your organization's NFC credentials are unique to the physical card (anti-clone measures, rolling codes, challenge-response) or are simply a static UID that any blank tag can impersonate.

---

## Card Emulation

<!-- screenshot: rfid_emulate.png -->

Puts the PN532 into **NFC-A target mode** (TgInitAsTarget), making CYM appear to a reader as an NFC card. Emulates any card from the RFID storage library on the SD card.

### What it responds to
- **READ (0x30)** — returns page data from the stored card image
- **GET_VERSION (0x60)** — returns a static NTAG213 response
- Unknown commands → NAK

> **Limitation:** MIFARE Classic authentication (CRYPTO1) is not emulated — the PN532 target mode has no CRYPTO1 engine. Readers that require crypto auth after UID selection will fail. Emulation is most effective against readers that only check UID presence.

### Research use cases

**Reader validation testing**  
Present CYM emulating a cloned card UID to the access reader. This determines whether the reader performs only UID check (vulnerable) or requires crypto challenge-response (resistant). You get the answer in one tap.

**Physical access control penetration test**  
During an authorized physical pen test, emulate a cloned credential and attempt to access restricted areas. The test proves or disproves the hypothesis that a cloned card grants access — and captures it in the assessment report.

**Reader firmware behavior analysis**  
Some readers send unusual APDU sequences after UID selection. Running emulation mode while monitoring the PN532 I2C logs (available in ESP-IDF serial output) reveals exactly what commands the reader sends — useful for reverse-engineering proprietary reader protocols.

---

## Key Test — Authentication Attempt

<!-- screenshot: rfid_keytest.png -->

Attempts MIFARE Classic authentication against a detected card using a configurable list of known-default and common keys (Key A and Key B for each sector).

### Research use cases

**Default key detection**  
Many deployed MIFARE Classic access cards — even in enterprise environments — still have factory-default keys (`FF FF FF FF FF FF`, `A0 A1 A2 A3 A4 A5`, etc.) on one or more sectors. Key Test checks all common defaults and highlights which sectors authenticate with default keys, exposing the data in those sectors to anyone with a reader.

**Sector mapping for cloning research**  
Before a full MIFARE Classic clone (which requires knowing the keys for every sector), Key Test identifies which sectors you can access with known keys. Sectors with readable data under default keys may contain cardholder data, facility codes, or access group identifiers.

**Credential system audit**  
Card issuers who claim to use custom keys can be verified — if Key Test cracks any sector with a well-known key, the issuer's key management practices are deficient.
