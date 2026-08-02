# CYM-NM28C5 LVGL text / typography rules

## Em dash U+2014 (—) is BANNED in all LVGL label strings

`lv_font_montserrat_*` variants compiled for this project do NOT include the em dash
glyph (U+2014).  Any string containing `—` that is passed to an LVGL text function
(`lv_label_set_text`, `lv_textarea_set_text`, `snprintf` → LVGL, etc.) will render
as a missing-glyph □ block on screen.

**Rule:** Use ASCII hyphen `-` everywhere an em dash would appear in a UI string.

```c
// WRONG
lv_label_set_text(lbl, "No card — try again");

// CORRECT
lv_label_set_text(lbl, "No card - try again");
```

This applies to:
- `lv_label_set_text` / `lv_label_set_text_fmt`
- `lv_textarea_set_text` / `lv_textarea_add_text`
- Any `snprintf(buf, ...)` whose result goes to an LVGL widget
- Status strings returned by helper functions that end up in LVGL labels

**Exceptions (not LVGL — em dash is fine):**
- `ESP_LOGI/W/E/D` log strings (serial output only)
- `fprintf(f, ...)` / `fwrite` to SD card files
- C comments

## Other non-ASCII typography to avoid in LVGL strings

| Character | U+     | Notes |
|-----------|--------|-------|
| Em dash   | U+2014 | Use `-` |
| En dash   | U+2013 | Use `-` |
| Left angle quotation ‹ | U+2039 | Use `<` or omit |
| Smart quotes " " ' ' | U+201C/D, U+2018/9 | Use straight `"` / `'` |
| Ellipsis … | U+2026 | Use `...` |
| Non-breaking space | U+00A0 | Use regular space |

When in doubt: if a character is not printable ASCII (0x20–0x7E), it is at risk
of being missing from the compiled font.  Default to plain ASCII in UI strings.

## Symbol glyphs

LVGL built-in symbols (`LV_SYMBOL_*`) are compiled into specific font files only.
In this build, `lv_font_montserrat_16` does NOT have the built-in symbol range.
Use `MY_SYMBOL_*` from `lv_extra_symbols` with `&lv_extra_symbols` as the fallback
font for FontAwesome glyphs (key U+F084, microchip U+F2DB, database U+F1C0, etc.).
