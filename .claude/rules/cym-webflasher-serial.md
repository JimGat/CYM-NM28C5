# CYM-NM28C5 web flasher — serial port & reset patterns

All future changes to `ESP32C5/docs/index.html` must follow these rules,
validated through multiple iterations against real ESP32-C5 USB Serial/JTAG hardware.

## ESP32 auto-reset wiring (USB Serial/JTAG)

| Signal | Maps to | Effect |
|--------|---------|--------|
| `requestToSend: true`  | EN LOW  | Chip enters reset |
| `requestToSend: false` | EN HIGH | Chip releases reset and boots |
| `dataTerminalReady: false` | IO0 HIGH | Boots **firmware** (not ROM bootloader) |
| `dataTerminalReady: true`  | IO0 LOW  | Boots **ROM bootloader** (download mode) |

To reset to **firmware**: assert RTS with DTR false, wait 100 ms, release RTS.  
To enter **download mode**: assert both RTS + DTR, release RTS (keeps DTR = IO0 LOW).

## Mandatory reset calls

### In `connectMonitor()` — after `port.open()`
```javascript
// Reset board to firmware so monitor sees a clean boot sequence
try {
    await state.monitorPort.setSignals({ dataTerminalReady: false, requestToSend: true });
    await sleep(100);
    await state.monitorPort.setSignals({ dataTerminalReady: false, requestToSend: false });
    await sleep(400); // wait for ESP32-C5 to finish booting before reading
} catch {}
```

### In `disconnect()` — before `esploader.disconnect()`
```javascript
// Reset board to firmware BEFORE tearing down the transport.
// Use direct setSignals() — NOT esploader.hardResetToFirmware().
// See "Why setSignals() not hardResetToFirmware()" below.
try {
    await state.port.setSignals({ dataTerminalReady: false, requestToSend: true });
    await sleep(100);
    await state.port.setSignals({ dataTerminalReady: false, requestToSend: false });
} catch {}
// THEN tear down the loader
if (state.esploader) {
    try { await Promise.race([state.esploader.disconnect(), sleep(800)]); } catch {}
}
try { await state.port.close(); } catch {}
```

## Why `setSignals()` not `esploader.hardResetToFirmware()`

After `runStub()`, `state.esploader` is reassigned to a **stub loader** instance.
The stub may not implement `hardResetToFirmware()`. Both the primary call and
the `hardReset()` fallback then throw and are caught silently — no reset fires.
Direct `port.setSignals()` works unconditionally while the port is open.

## Flash cleanup — NEVER call `esploader.disconnect()` early

```javascript
// WRONG — disturbs port stream state, making later setSignals() fail silently:
if (state.esploader) {
    try { await Promise.race([state.esploader.disconnect(), sleep(800)]); } catch {}
}
state.esploader = null;
// ... later in disconnect(): setSignals() silently fails, no reset fires ...

// CORRECT — leave loader alive; let disconnect() own the full teardown:
// (no esploader.disconnect() call in flash cleanup)
state.chip = null;
// state.esploader stays set, state.port stays open
// state.connected stays true → Disconnect button routes to disconnect(), not connect()
```

**Why:** `esploader.disconnect()` releases the port's SLIP stream locks. Even though
`port.close()` is not called, the lock-release leaves the port in a state where
subsequent `setSignals()` calls throw a caught exception — silently doing nothing.
Keeping the loader alive preserves the clean port state that `setSignals()` needs.

## Post-flash UI state

After a successful flash, set:
- `state.chip = null`
- `state.connected = true` ← **keep true**; do not set false
- `state.esploader` ← **keep set** (alive)
- `state.port` ← **keep open**
- `state.lastPort = state.port` (for monitor reuse)
- `ui.flashBtn.disabled = true` (can't reflash without fresh connect)
- `ui.connectBtn.disabled = false` (shows "Disconnect", routes to disconnect())

**Do NOT** set `state.connected = false` after flash. If you do, clicking the button
that visually reads "Disconnect" calls `connect()` → `requestPort()` picker instead
of `disconnect()` — wrong action on the first click.

## ESPLoader stream teardown

Use the library's own `disconnect()` (not manual `transport.reader.cancel()`):
```javascript
// CORRECT — releases all internal piped transform streams:
try { await Promise.race([state.esploader.disconnect(), sleep(800)]); } catch {}

// WRONG — insufficient; ESPLoader has internal pipelines not reachable this way:
try { await state.esploader?.transport?.reader?.cancel?.(); } catch {}
try { state.esploader?.transport?.writer?.releaseLock?.(); } catch {}
```

Manual reader/writer manipulation was the original broken approach (page < 2.9.0).
`ESPLoader.disconnect()` is the only way to properly release all internal stream locks.

## PAGE_VERSION

Bump `PAGE_VERSION` (semver string in `index.html`) for every change to the flasher,
even if no firmware binary changes. Users rely on this to confirm which version is live.
