cmake_minimum_required(VERSION 3.16)

# Add linker flag globally (needed for duplicate symbols in ROM)
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -Wl,-zmuldefs")

# ── Single source of truth for firmware version ──────────────────────────────
# Update ONLY this line when bumping the version. It is automatically propagated
# to both the IDF boot log (app_init: App version) and to the FW_VERSION macro
# used throughout the firmware — no need to edit wifi_common.h separately.
set(PROJECT_VER "v2.13.42")

# Bootstrap ESP-IDF build system
include($ENV{IDF_PATH}/tools/cmake/project.cmake)

# Ensure linker option is applied IDF-wide to the final app link
idf_build_set_property(LINK_OPTIONS "-Wl,-zmuldefs" APPEND)

# Make 'main' headers (e.g., lvgl_memory.h) visible globally for components that include by name
idf_build_set_property(COMPILE_OPTIONS "-I${CMAKE_SOURCE_DIR}/main" APPEND)

# Suppress warnings-as-errors globally (pre-existing dead code warnings in main.c)
# The codebase has pre-existing unused function warnings that should be cleaned up separately
idf_build_set_property(COMPILE_OPTIONS "-Wno-error" APPEND)

project(CYM-NM28C5)

# Expose PROJECT_VER as FW_VERSION compile definition so wifi_common.h picks it
# up without a separate hardcoded string.  All translation units see this.
idf_build_set_property(COMPILE_DEFINITIONS "FW_VERSION=\"${PROJECT_VER}\"" APPEND)

# ===== MITM: allow lwIP to forward packets back out the same WiFi interface =====
idf_component_get_property(lwip_lib lwip COMPONENT_LIB)
target_compile_definitions(${lwip_lib} PRIVATE IP_FORWARD_ALLOW_TX_ON_RX_NETIF=1)

# ===== POST-BUILD: copy binaries to binaries-esp32c5 every build =====
set(EXPORT_DIR "${CMAKE_SOURCE_DIR}/binaries-esp32c5")
file(MAKE_DIRECTORY "${EXPORT_DIR}")

# gen_<PROJECT>_binary is the ESP-IDF target that produces the .bin file.
# POST_BUILD on it fires unconditionally after every successful binary generation.
add_custom_command(
    TARGET "gen_${CMAKE_PROJECT_NAME}_binary" POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy
            "${CMAKE_BINARY_DIR}/${CMAKE_PROJECT_NAME}.bin"
            "${EXPORT_DIR}/${CMAKE_PROJECT_NAME}.bin"
    COMMAND ${CMAKE_COMMAND} -E copy
            "${CMAKE_BINARY_DIR}/bootloader/bootloader.bin"
            "${EXPORT_DIR}/bootloader.bin"
    COMMAND ${CMAKE_COMMAND} -E copy
            "${CMAKE_BINARY_DIR}/partition_table/partition-table.bin"
            "${EXPORT_DIR}/partition-table.bin"
    # Merge bootloader + partition table + firmware into one flat image.
    # Flash at 0x0000 with any flasher that accepts a full binary.
    COMMAND python -m esptool --chip esp32c5 merge_bin
            -o "${EXPORT_DIR}/${CMAKE_PROJECT_NAME}-full.bin"
            --flash_mode dio --flash_freq 80m --flash_size 16MB
            0x2000  "${CMAKE_BINARY_DIR}/bootloader/bootloader.bin"
            0x8000  "${CMAKE_BINARY_DIR}/partition_table/partition-table.bin"
            0x10000 "${CMAKE_BINARY_DIR}/${CMAKE_PROJECT_NAME}.bin"
    COMMENT "Copying firmware and generating merged full flash image in ${EXPORT_DIR}"
)

# ===== POST-BUILD: update memory-budget.md from the linker map =====
# Parses build/CYM-NM28C5.map and rewrites the auto-update tables in
# docs/memory-budget.md so the committed doc always matches the binary.
# Requires Python 3 (available in the IDF virtual-env).
find_package(Python3 QUIET COMPONENTS Interpreter)
if(Python3_FOUND)
    # Get the binary size at configure time (we use file(SIZE …) at build time via generator expression)
    # Pass the .bin path; the script stats it for the binary size.
    add_custom_command(
        TARGET "gen_${CMAKE_PROJECT_NAME}_binary" POST_BUILD
        COMMAND ${Python3_EXECUTABLE}
                "${CMAKE_SOURCE_DIR}/tools/update_memory_map.py"
                "${CMAKE_BINARY_DIR}/${CMAKE_PROJECT_NAME}.map"
                "${CMAKE_SOURCE_DIR}/docs"
                "${PROJECT_VER}"
                "${EXPORT_DIR}/${CMAKE_PROJECT_NAME}.bin"
        COMMENT "Updating docs/memory-budget.md from linker map"
        VERBATIM
    )
else()
    message(STATUS "[memory_map] Python3 not found — skipping memory-budget.md update")
endif()
