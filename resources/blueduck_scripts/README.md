# BlueDuck Script Library

Copy `.duck` files to `/sdcard/lab/ble/blueduck/scripts/` on the device SD card.

## Scripts

| File | Target | What it does |
|------|--------|--------------|
| `android_search.duck` | Android | HOME → global search overlay → query |
| `android_chrome_search.duck` | Android | HOME → open Chrome → Google search URL |
| `android_settings_search.duck` | Android | HOME → open Settings → search "bluetooth" |

## DuckyScript Command Reference

### Flow
| Command | Example | Notes |
|---------|---------|-------|
| `REM` | `REM comment` | Comment line, ignored |
| `DELAY` | `DELAY 1000` | Wait ms |
| `DEFAULT_DELAY` | `DEFAULT_DELAY 100` | Added after every command |
| `REPEAT` | `REPEAT 3` | Repeat last command N times |

### Typing
| Command | Example | Notes |
|---------|---------|-------|
| `STRING` | `STRING hello world` | Type text |
| `STRINGLN` | `STRINGLN hello` | Type text + ENTER |
| `HUMAN_MODE` | `HUMAN_MODE ON` | Enable variable-speed typing |
| `HUMAN_SPEED` | `HUMAN_SPEED NORMAL` | `SLOW` / `NORMAL` / `FAST` |

### Keys
```
ENTER  BACKSPACE  TAB  SPACE  ESCAPE  DELETE
UP  DOWN  LEFT  RIGHT  HOME  END  PAGEUP  PAGEDOWN
CAPS_LOCK  F1-F12
```

### Modifiers (combine with a key)
```
GUI r          → Windows Run dialog / Android Home
CTRL c         → Copy
CTRL v         → Paste
CTRL-ALT DELETE
ALT F4
GUI-SHIFT s    → Windows screenshot
```

## Tips for Mobile Targets

- `HOME` on Android returns to launcher; most launchers open search when you immediately type
- Add `DELAY 1000`+ after `HOME` — launcher animation needs to complete before keystrokes land
- `DELAY 1500`+ after opening an app — wait for it to fully load before typing into it
- Use `HUMAN_MODE ON` + `HUMAN_SPEED SLOW` for maximum authenticity
- Test with the Wireless Keyboard persona first (phones expect a keyboard to type)
