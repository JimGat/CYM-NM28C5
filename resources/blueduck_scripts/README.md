# BlueDuck Script Library

Copy `.duck` files to `/sdcard/lab/ble/blueduck/scripts/` on the device SD card.

## Scripts

| File | Target | What it does |
|------|--------|--------------|
| `android_search.duck` | Android | Win+H → home, ENTER on Google search widget |
| `android_chrome_search.duck` | Android | Win+B → browser, Ctrl+L → address bar, Google search |
| `android_settings_search.duck` | Android | Win+H → home, type "settings" to open, search bluetooth |
| `android_browser_url.duck` | Android | Win+B → browser, Ctrl+L → address bar, navigate URL |
| `android_notifications.duck` | Android | Win+N → open notification shade |
| `android_rickroll.duck` | Android | Win+B → browser → Rick Astley — Never Gonna Give You Up |

---

## Android Physical Keyboard Shortcuts

### Meta / Win / Search Key (⊞)

Modifier key is called **Search** on ChromeOS keyboards, **Windows/Win** on PC keyboards,
**Command** on Mac keyboards. All map to the same HID modifier bit (Left GUI, 0x08).

#### System Navigation

| Shortcut | Action | Notes |
|----------|--------|-------|
| Win+H | Home screen | Confirmed Samsung One UI |
| Win+Return | Home screen | Alternate |
| Win+Tab | Recent apps / App switcher | |
| Win+~ | Back button | |
| Win+N | Notification shade | Confirmed Samsung One UI |
| Win+I | System Settings | |
| Win+L | Lock screen | |
| Win+T | Toggle taskbar | Tablets / DeX |
| Win+/ | Show keyboard shortcut menu | Android 14+ |
| Win+A | Google Assistant | |
| Win+Space | Switch input method | |
| Win+Ctrl+← | Split screen left | Tablets |
| Win+Ctrl+→ | Split screen right | Tablets |
| Win+Ctrl+S | Screenshot | |
| Win+Ctrl+N | Quick memo | |

#### App Launchers (Win + letter)

These launch or switch to specific apps. Behavior is manufacturer- and version-dependent —
Samsung One UI results confirmed below; other launchers may differ.

| Shortcut | Generic Android | Samsung One UI (confirmed) |
|----------|----------------|---------------------------|
| Win+B | Default browser | Default browser |
| Win+C | Contacts | Contacts |
| Win+E | Email | Email |
| Win+G | Gmail | Gmail |
| Win+H | Home screen | Home screen |
| Win+K | Calendar | Calendar |
| Win+M | Maps | Maps |
| Win+P | Music player | Music player |
| Win+S | Messages | Messages |
| Win+U | Calculator | Calculator |
| Win+Y | YouTube | **Smart View** (screen mirroring) |

> **Samsung note:** Win+Y opens Smart View on Samsung One UI, not YouTube.
> Use `GUI b` + `CTRL l` + `youtube.com` to reach YouTube reliably.

---

### Ctrl Key

| Shortcut | Action | Notes |
|----------|--------|-------|
| Ctrl+A | Select all | |
| Ctrl+C | Copy | |
| Ctrl+V | Paste | |
| Ctrl+X | Cut | |
| Ctrl+Z | Undo | |
| Ctrl+Y | Redo | |
| Ctrl+L | Focus browser address bar | Chrome, Firefox, Brave, Kiwi |
| Ctrl+K | Focus global search bar | Google Discover, Samsung Notes |
| Ctrl+T | New browser tab | |
| Ctrl+W | Close current tab | |
| Ctrl+Shift+T | Reopen last closed tab | |
| Ctrl+R | Refresh page | |
| Ctrl+Space | Switch input language | |
| Ctrl+Shift+Space | Previous input language | |
| Ctrl+Alt+Del | Reboot device | |

---

### Alt Key

| Shortcut | Action |
|----------|--------|
| Alt+Tab | Cycle recent apps (forward) |
| Alt+Shift+Tab | Cycle recent apps (backward) |
| Alt+Esc | Home screen (alternate) |
| Alt+Space | Insert special character |
| Alt+Del | Delete entire line |

---

### Navigation / Other

| Key | Action |
|-----|--------|
| Esc | Back / dismiss dialog |
| Tab | Move focus forward through UI elements |
| Shift+Tab | Move focus backward |
| Shift+Arrow | Select text |
| Shift+Space | Switch input language |

---

## DuckyScript Command Reference

### Flow

| Command | Example | Notes |
|---------|---------|-------|
| `REM` | `REM comment` | Comment, ignored |
| `DELAY` | `DELAY 1000` | Wait milliseconds |
| `DEFAULT_DELAY` | `DEFAULT_DELAY 100` | Appended after every command |
| `REPEAT` | `REPEAT 3` | Repeat last command N times |

### Typing

| Command | Example | Notes |
|---------|---------|-------|
| `STRING` | `STRING hello world` | Type text character by character |
| `STRINGLN` | `STRINGLN hello` | Type text then press ENTER |
| `HUMAN_MODE` | `HUMAN_MODE ON` | Enable variable-speed typing |
| `HUMAN_SPEED` | `HUMAN_SPEED NORMAL` | `SLOW` / `NORMAL` / `FAST` |

### Named Keys

```
ENTER  BACKSPACE  TAB  SPACE  ESC  DELETE  INSERT
UP  DOWN  LEFT  RIGHT  HOME  END  PAGEUP  PAGEDOWN
CAPS_LOCK  NUM_LOCK  F1–F12
```

> **Android note:** `HOME` (HID 0x4A) is **cursor home** (beginning of line), NOT the
> Android home button. Use `GUI h` (Win+H) to go to the Android home screen.

### Modifier Combos

Syntax: `MODIFIER key` (space-separated). Multiple modifiers chain with dashes before the key.

```
GUI h              → Win+H (Android home screen)
GUI b              → Win+B (open default browser)
GUI n              → Win+N (open notifications)
CTRL l             → Ctrl+L (focus browser address bar)
CTRL c             → Copy
CTRL v             → Paste
CTRL-ALT DELETE    → Reboot
ALT TAB            → App switcher
GUI-SHIFT s        → Windows screenshot (Windows target)
```

**Supported modifiers:** `GUI` / `WINDOWS` / `COMMAND`, `CTRL` / `CONTROL`,
`ALT` / `OPTION`, `SHIFT`

---

## Tips for Android Targets

- Use `GUI h` (Win+H) to go to the home screen — bare `GUI` alone is not a valid command
- Use `GUI b` + `CTRL l` for reliable browser navigation on any launcher (no launcher search dependency)
- Samsung One UI in keyboard-nav mode **does not** open a search overlay when typing from home — use the browser approach instead
- Add `DELAY 1500`+ after `GUI b` — wait for the browser to fully load before `CTRL l`
- Add `DELAY 500`+ after `CTRL l` — address bar focus animation needs to complete
- Use `HUMAN_MODE ON` + `HUMAN_SPEED SLOW` for maximum authenticity
- Test with the **Wireless Keyboard** persona first (phones expect a keyboard to type, not a mouse)
