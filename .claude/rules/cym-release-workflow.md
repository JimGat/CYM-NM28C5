# CYM-NM28C5 release/test workflow guardrails

When Jim asks for a change that he will test from GitHub, do the complete test-build handoff, not just source edits.

1. Work on the dev host repo: `/home/dev/projects/CYM-NM28C5`.
2. Stay on branch `Jimgat_Dev` unless Jim explicitly asks for `main`/release flow.
3. Before building a test binary, bump the PATCH version in `ESP32C5/CMakeLists.txt`:
   - `set(PROJECT_VER "vX.Y.Z")`
   - **Each board build gets its own version bump** — no two binaries may share a version number.
   - Do not bump MAJOR or MINOR without explicit approval.
4. Build for the target board using the command for that board (see table below).
5. The CMake post-build hook copies firmware into the board-specific output directory and generates the merged full image. Verify all four tracked binaries changed.
6. Before commit, verify the binary contains the expected version string.
7. Update the board-specific manifest JSON to match the new version.
8. Stage board-specific files only (never `git add -A`), commit, and push to `origin Jimgat_Dev`.
9. Never run `idf.py flash`, `esptool write-flash`, or `git push --force` unless Jim explicitly overrides.

---

## Multi-Board Build Reference (ESP32C5/)

All builds run from `ESP32C5/`. Load ESP-IDF first: `. /home/dev/esp/esp-idf/export.sh`

### NM-CYD-C5 (original CYM board)

```bash
idf.py -B build_nm-cyd-c5 \
  -DSDKCONFIG=build_nm-cyd-c5/sdkconfig \
  "-DSDKCONFIG_DEFAULTS=sdkconfig.defaults;sdkconfig.defaults.nm-cyd-c5" \
  build
```

| Item | Value |
|------|-------|
| Output dir | `ESP32C5/binaries-esp32c5/` |
| App binary | `CYM-NM28C5.bin` |
| Full image | `CYM-NM28C5-full.bin` |
| Manifest | `ESP32C5/docs/manifest.json` |
| Web flasher board | `nm-cyd-c5` |
| Flash size | 16 MB |

Verify: `strings binaries-esp32c5/CYM-NM28C5.bin | grep vX.Y.Z`

Stage per commit:
```
ESP32C5/CMakeLists.txt
ESP32C5/docs/manifest.json
ESP32C5/docs/memory-budget.md
ESP32C5/binaries-esp32c5/CYM-NM28C5.bin
ESP32C5/binaries-esp32c5/CYM-NM28C5-full.bin
ESP32C5/binaries-esp32c5/bootloader.bin
ESP32C5/binaries-esp32c5/partition-table.bin
```
(plus any source files changed for that board)

---

### WS-C5-28 (Waveshare ESP32-C5-Touch-LCD-2.8)

```bash
idf.py -B build_ws-c5-28 \
  -DSDKCONFIG=build_ws-c5-28/sdkconfig \
  "-DSDKCONFIG_DEFAULTS=sdkconfig.defaults;sdkconfig.defaults.ws-c5-28" \
  build
```

| Item | Value |
|------|-------|
| Output dir | `ESP32C5/binaries-ws-c5-28/` |
| App binary | `CYM-WS-C5-28.bin` |
| Full image | `CYM-WS-C5-28-full.bin` |
| Manifest | `ESP32C5/docs/manifest.ws-c5-28.json` |
| Web flasher board | `ws-c5-28` |
| Flash size | 32 MB |

Verify: `strings binaries-ws-c5-28/CYM-WS-C5-28.bin | grep vX.Y.Z`

Stage per commit:
```
ESP32C5/CMakeLists.txt
ESP32C5/docs/manifest.ws-c5-28.json
ESP32C5/docs/memory-budget.md
ESP32C5/binaries-ws-c5-28/CYM-WS-C5-28.bin
ESP32C5/binaries-ws-c5-28/CYM-WS-C5-28-full.bin
ESP32C5/binaries-ws-c5-28/bootloader.bin
ESP32C5/binaries-ws-c5-28/partition-table.bin
```
(plus any source files changed for that board)

---

## Version numbering across boards

The single `PROJECT_VER` in `ESP32C5/CMakeLists.txt` is shared but each board build
increments it before building. Workflow when building multiple boards in one session:

1. Bump version → v2.13.X → build NM-CYD-C5 → commit NM-CYD-C5 files
2. Bump version → v2.13.X+1 → build WS-C5-28 → commit WS-C5-28 files

Never build two different boards at the same version number.

---

## Release to main — MANDATORY binary attachment

When merging to main and creating a GitHub release, attach ALL binaries from ALL active boards:

```bash
gh release create vX.Y.Z \
  --target main \
  --title "..." \
  --notes "..." \
  ESP32C5/binaries-esp32c5/CYM-NM28C5.bin \
  ESP32C5/binaries-esp32c5/CYM-NM28C5-full.bin \
  ESP32C5/binaries-esp32c5/bootloader.bin \
  ESP32C5/binaries-esp32c5/partition-table.bin \
  ESP32C5/binaries-ws-c5-28/CYM-WS-C5-28.bin \
  ESP32C5/binaries-ws-c5-28/CYM-WS-C5-28-full.bin \
  ESP32C5/binaries-ws-c5-28/bootloader.bin \
  ESP32C5/binaries-ws-c5-28/partition-table.bin
```

Note: the two `bootloader.bin` and `partition-table.bin` files differ between boards
(16 MB vs 32 MB flash config). Use `--name` flags if GitHub CLI requires disambiguation.

`*-full.bin` is a merged flat image (bootloader + partition table + firmware) generated
by the CMake post-build hook. Flash at address `0x0000` with any full-binary flasher.
Never create a release without all binaries from all boards attached.

---

## Web flasher (ESP32C5/docs/index.html)

The flasher supports board selection at runtime:

| UI selector | Manifest loaded | Binary directory |
|-------------|----------------|-----------------|
| NM-CYD-C5 | `docs/manifest.json` | `binaries-esp32c5/` |
| WS-C5-28 | `docs/manifest.ws-c5-28.json` | `binaries-ws-c5-28/` |

To add a new board to the web flasher, add an entry to the `BOARDS` object in `docs/index.html`
and create the corresponding `docs/manifest.<board>.json`.

---

## Runtime crash discipline

- Build success is not enough for LVGL/task/lifecycle changes.
- For sniffer/capture/UI teardown work, specifically review task ownership, timers, global pointers, cancellation, and use-after-free risks before publishing a binary.
