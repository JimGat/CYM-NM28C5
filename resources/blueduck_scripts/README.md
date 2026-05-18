# BlueDuck Script Library

Copy `.duck` files to `/sdcard/lab/ble/blueduck/scripts/` on the device SD card.

---

## Scripts

### Android

| File | What it does |
|------|--------------|
| `android_search.duck` | Win+H → home, ENTER on Google search widget |
| `android_chrome_search.duck` | Win+B → browser, Ctrl+L → address bar, Google search |
| `android_settings_search.duck` | Win+H → home, type "settings" → search bluetooth |
| `android_browser_url.duck` | Win+B → browser, Ctrl+L → navigate URL |
| `android_notifications.duck` | Win+N → open notification shade |
| `android_rickroll.duck` | Win+B → browser → Rick Astley |

### Windows

| File | What it does |
|------|--------------|
| `windows_rickroll.duck` | Win+R → Run dialog → browser → Rick Astley |
| `windows_lock.duck` | Win+L → lock workstation immediately |
| `windows_notepad_msg.duck` | Win+R → Notepad → type awareness message |
| `windows_screenshot.duck` | Win+Shift+S → Snip & Sketch screen capture overlay |
| `windows_sysinfo.duck` | Win+Pause → System Information panel |
| `windows_task_manager.duck` | Ctrl+Shift+Esc → Task Manager (no UAC screen) |
| `windows_open_browser.duck` | Win+R → Run dialog → default browser at target URL |

---

## Android Physical Keyboard Shortcuts

### Meta / Win / Search Key (⊞)

The modifier key is called **Search** on ChromeOS, **Windows/Win** on PC keyboards,
**Command** on Mac keyboards. All map to the same HID modifier bit (Left GUI, 0x08).

#### System Navigation

| Shortcut | Action | Confirmed |
|----------|--------|-----------|
| Win+H | Home screen | Samsung One UI ✓ |
| Win+Return | Home screen (alternate) | |
| Win+Tab | Recent apps / App switcher | |
| Win+~ | Back button | |
| Win+N | Notification shade | Samsung One UI ✓ |
| Win+I | System Settings | |
| Win+L | Lock screen | |
| Win+T | Toggle taskbar (tablets) | |
| Win+/ | Show keyboard shortcut menu (Android 14+) | |
| Win+A | Google Assistant | |
| Win+Space | Switch input method | |
| Win+Ctrl+← | Split screen left (tablets) | |
| Win+Ctrl+→ | Split screen right (tablets) | |
| Win+Ctrl+S | Screenshot | |
| Win+Ctrl+N | Quick memo | |

#### App Launchers (Win + letter)

Behavior is manufacturer- and version-dependent. Samsung One UI results confirmed below.

| Shortcut | Generic Android | Samsung One UI |
|----------|----------------|----------------|
| Win+B | Default browser | Default browser ✓ |
| Win+C | Contacts | Contacts ✓ |
| Win+E | Email | Email |
| Win+G | Gmail | Gmail |
| Win+H | Home screen | Home screen ✓ |
| Win+K | Calendar | Calendar |
| Win+M | Maps | Maps |
| Win+N | Notifications | Notifications ✓ |
| Win+P | Music player | Music player |
| Win+S | Messages | Messages ✓ |
| Win+U | Calculator | Calculator |
| Win+Y | YouTube | **Smart View** (screen mirroring) ✓ |

> **Samsung note:** Win+Y opens Smart View on Samsung One UI, not YouTube.
> Use `GUI b` + `CTRL l` + `youtube.com` to reach YouTube reliably.

### Android — Ctrl Key

| Shortcut | Action |
|----------|--------|
| Ctrl+A | Select all |
| Ctrl+C | Copy |
| Ctrl+V | Paste |
| Ctrl+X | Cut |
| Ctrl+Z | Undo |
| Ctrl+Y | Redo |
| Ctrl+L | Focus browser address bar (Chrome, Firefox, Brave) |
| Ctrl+K | Focus global search bar |
| Ctrl+T | New browser tab |
| Ctrl+W | Close current tab |
| Ctrl+Shift+T | Reopen last closed tab |
| Ctrl+R | Refresh page |
| Ctrl+Space | Switch input language |
| Ctrl+Shift+Space | Previous input language |
| Ctrl+Alt+Del | Reboot device |

### Android — Alt Key

| Shortcut | Action |
|----------|--------|
| Alt+Tab | Cycle recent apps (forward) |
| Alt+Shift+Tab | Cycle recent apps (backward) |
| Alt+Esc | Home screen (alternate) |
| Alt+Space | Insert special character |
| Alt+Del | Delete entire line |

---

## Windows 10 / 11 Keyboard Shortcuts

### Windows Key (Win / GUI)

#### System & Navigation

| Shortcut | Action |
|----------|--------|
| Win+D | Show / hide desktop |
| Win+L | **Lock workstation** |
| Win+E | File Explorer |
| Win+I | Settings |
| Win+R | **Run dialog** |
| Win+S | Windows Search |
| Win+X | Power User menu (Quick Link) |
| Win+A | Quick Settings panel |
| Win+Tab | Task View |
| Win+V | Clipboard History |
| Win+Pause | System Information / About |
| Win+. or Win+; | Emoji & Symbols panel |
| Win+Space | Switch input language |
| Win+T | Cycle taskbar apps |
| Win+1–9 | Open/launch pinned taskbar app by position |
| Win+Shift+S | **Snip & Sketch screenshot overlay** |
| Win+Shift+Arrow | Move window between displays |
| Win+Up | Maximize active window |
| Win+Down | Minimize / restore window |
| Win+Left | Snap window left |
| Win+Right | Snap window right |
| Win+Ctrl+D | Create new virtual desktop |
| Win+Ctrl+←/→ | Switch virtual desktops |

#### Windows 11 Only

| Shortcut | Action |
|----------|--------|
| Win+W | Widgets pane |
| Win+Z | Snap Layouts |
| Win+C | Microsoft Copilot |
| Win+N | Notification Center |
| Win+H | Voice Typing |
| Win+K | Cast / Connect panel |
| Win+G | Xbox Game Bar |
| Win+P | Display projection settings |
| Win+Alt+R | Start / stop game recording |

#### Accessibility

| Shortcut | Action |
|----------|--------|
| Win+U | Accessibility Settings |
| Win++ | Activate Magnifier / zoom in |
| Win+- | Zoom out (Magnifier) |
| Win+Esc | Deactivate Magnifier |
| Win+Ctrl+N | Narrator (screen reader) |
| Win+Ctrl+S | Speech Recognition |
| Win+Ctrl+O | On-Screen Keyboard |
| Win+Ctrl+C | Toggle Color Filters |

### Windows — Ctrl Key

| Shortcut | Action |
|----------|--------|
| Ctrl+A | Select all |
| Ctrl+C | Copy |
| Ctrl+V | Paste |
| Ctrl+X | Cut |
| Ctrl+Z | Undo |
| Ctrl+Y | Redo |
| Ctrl+S | Save |
| Ctrl+P | Print |
| Ctrl+F | Find |
| Ctrl+L | Jump to address bar (browser / Explorer) |
| Ctrl+N | New window |
| Ctrl+W | Close window / tab |
| Ctrl+T | New browser tab |
| Ctrl+Shift+T | Reopen last closed tab |
| Ctrl+R | Refresh |
| Ctrl+Shift+Esc | **Task Manager (direct, no UAC screen)** |
| Ctrl+Esc | Open Start menu |
| Ctrl+Shift+N | New folder (File Explorer) |
| Ctrl+D | Delete selected (File Explorer) |
| Ctrl+Alt+Del | Security screen (cannot be intercepted by HID) |

### Windows — Alt Key

| Shortcut | Action |
|----------|--------|
| Alt+Tab | Switch between open applications |
| Alt+Esc | Cycle windows in taskbar order |
| Alt+F4 | Close active window / shutdown dialog on desktop |
| Alt+Spacebar | Active window shortcut menu |
| Alt+F8 | Show password on sign-in screen |
| Alt+Enter | File properties (Explorer) |
| Alt+← / → | Back / Forward (Explorer, browser) |
| Alt+Up | Go to parent folder (Explorer) |
| Alt+D | Select address bar (Explorer) |
| Alt+P | Toggle preview pane (Explorer) |

### Windows — Function Keys

| Key | Action |
|-----|--------|
| F2 | Rename selected item |
| F3 / Ctrl+F | Find / search |
| F4 | Select address bar (Explorer) |
| F5 | Refresh |
| F11 | Toggle fullscreen |
| Shift+F10 | Open context menu (right-click) |

### Windows Run Dialog — Useful Commands

Open with `GUI r`, type command, press ENTER.

| Command | Opens |
|---------|-------|
| `notepad` | Notepad |
| `calc` | Calculator |
| `explorer` | File Explorer |
| `cmd` | Command Prompt |
| `powershell` | PowerShell |
| `taskmgr` | Task Manager |
| `msinfo32` | System Information |
| `devmgmt.msc` | Device Manager |
| `eventvwr` | Event Viewer |
| `services.msc` | Services |
| `regedit` | Registry Editor |
| `control` | Control Panel |
| `mstsc` | Remote Desktop |
| `msconfig` | System Configuration |
| `diskmgmt.msc` | Disk Management |
| `compmgmt.msc` | Computer Management |
| `https://...` | Opens URL in default browser |
| `msedge https://...` | Opens URL in Edge |
| `chrome https://...` | Opens URL in Chrome (if installed) |

> **HID note:** `Ctrl+Alt+Del` cannot be sent by a HID keyboard device on Windows —
> it is intercepted at the firmware/OS level. Use `Ctrl+Shift+Esc` to open Task Manager
> directly without going through the security screen.

---

## iOS / iPhone Keyboard Shortcuts (External Keyboard)

*For testing — behavior confirmed on iOS 16+.*

### System Navigation

| Shortcut | Action |
|----------|--------|
| Cmd+H | Home screen |
| Cmd+Spacebar | Spotlight search |
| Fn+H | Home screen (alternate) |
| Fn+Up | App Switcher |
| Fn+N | Notification Center |
| Fn+C | Control Center |
| Fn+S | Activate Siri |
| Tab+L | Lock screen |
| Globe+N | Notifications |
| Globe+C | Control Center |

### Text Editing

| Shortcut | Action |
|----------|--------|
| Cmd+C | Copy |
| Cmd+X | Cut |
| Cmd+V | Paste |
| Cmd+Z | Undo |
| Cmd+Shift+Z | Redo |
| Cmd+A | Select all |
| Cmd+↑/↓ | Jump to document start / end |
| Cmd+←/→ | Jump to line start / end |
| Alt+←/→ | Move by word |
| Shift+Arrow | Select text |

### Safari

| Shortcut | Action |
|----------|--------|
| Cmd+L | Focus address bar |
| Cmd+T | New tab |
| Cmd+W | Close tab |
| Cmd+R | Refresh |
| Cmd+F | Find on page |
| Cmd+D | Add bookmark |
| Spacebar | Scroll down |
| Shift+Space | Scroll up |

### Navigation (Full Keyboard Access)

| Key | Action |
|-----|--------|
| Tab | Move forward through items |
| Shift+Tab | Move backward |
| Spacebar | Activate focused item |
| Escape | Back / dismiss |

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
| `STRINGLN` | `STRINGLN hello` | Type text then ENTER |
| `HUMAN_MODE` | `HUMAN_MODE ON` | Enable variable-speed typing |
| `HUMAN_SPEED` | `HUMAN_SPEED NORMAL` | `SLOW` / `NORMAL` / `FAST` |

### Named Keys

```
ENTER  BACKSPACE  TAB  SPACE  ESC  DELETE  INSERT
UP  DOWN  LEFT  RIGHT  HOME  END  PAGEUP  PAGEDOWN
CAPS_LOCK  NUM_LOCK  F1–F12
```

> **Android note:** `HOME` (HID 0x4A) is **cursor home** (beginning of line), NOT the
> Android home button. Use `GUI h` (Win+H) for the Android home screen.

### Modifier Combos

Syntax: `MODIFIER key` (space-separated). Chain multiple modifiers with dashes before the final key.

```
GUI r              → Win+R (Windows Run dialog)
GUI l              → Win+L (lock screen — Windows or Android)
GUI h              → Win+H (Android home / Windows Voice Typing on Win11)
GUI b              → Win+B (Android default browser)
GUI n              → Win+N (Android/Windows notifications)
CTRL l             → Ctrl+L (focus browser address bar)
CTRL-SHIFT ESC     → Ctrl+Shift+Esc (Windows Task Manager)
GUI-SHIFT s        → Win+Shift+S (Windows screenshot)
CTRL c             → Copy
CTRL v             → Paste
ALT TAB            → App switcher (Windows or Android)
ALT F4             → Close window (Windows)
```

**Supported modifiers:** `GUI` / `WINDOWS` / `COMMAND`, `CTRL` / `CONTROL`,
`ALT` / `OPTION`, `SHIFT`

---

## Tips

### Android
- Use `GUI h` to go home — bare `GUI` alone is unrecognised
- Use `GUI b` + `CTRL l` for browser navigation — more reliable than launcher search on Samsung One UI
- Samsung One UI in keyboard-nav mode **does not** open a search overlay when typing from home
- Wait `DELAY 1500`+ after `GUI b` for the browser to load before sending `CTRL l`
- Use **Wireless Keyboard** persona — phones expect a keyboard, not a mouse

### Windows
- `Win+R` → URL is the most reliable cross-browser approach (no need to know which browser is installed)
- `Ctrl+Alt+Del` **cannot** be sent via HID on Windows — use `Ctrl+Shift+Esc` for Task Manager
- `HUMAN_MODE OFF` is fine for Windows — most Windows machines don't rate-limit HID input

### iOS
- `Cmd+H` goes home; `Cmd+Space` opens Spotlight
- Test with **Wireless Keyboard** persona; iOS may prompt to trust an unrecognised input device
