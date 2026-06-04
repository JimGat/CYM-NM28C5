# CYM-NM28C5 release/test workflow guardrails

When Jim asks for a change that he will test from GitHub, do the complete test-build handoff, not just source edits.

1. Work on the dev host repo: `/home/dev/projects/CYM-NM28C5`.
2. Stay on branch `Jimgat_Dev` unless Jim explicitly asks for `main`/release flow.
3. Before building a test binary, bump only the PATCH version in `ESP32C5/CMakeLists.txt`:
   - `set(PROJECT_VER "vX.Y.Z")`
   - Do not bump MAJOR or MINOR without explicit approval.
4. Build from `ESP32C5` with ESP-IDF loaded:
   - `. /home/dev/esp/esp-idf/export.sh`
   - `idf.py build`
5. The CMake post-build hook copies firmware into `ESP32C5/binaries-esp32c5/`; verify the tracked binary changed.
6. Before commit, verify the binary contains the expected version:
   - `strings ESP32C5/binaries-esp32c5/CYM-NM28C5.bin | grep vX.Y.Z`
7. Commit source changes and the tracked binary together when practical, or use a clearly labeled binary follow-up commit.
8. Push to `origin Jimgat_Dev`.
9. Never run `idf.py flash`, `esptool write-flash`, or `git push --force` unless Jim explicitly overrides.

Runtime crash discipline:
- Build success is not enough for LVGL/task/lifecycle changes.
- For sniffer/capture/UI teardown work, specifically review task ownership, timers, global pointers, cancellation, and use-after-free risks before publishing a binary.
