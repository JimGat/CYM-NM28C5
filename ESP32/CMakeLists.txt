cmake_minimum_required(VERSION 3.16)

# ── Shared source: pull in all CYM components from the C5 source tree ─────────
# The ESP32 build reuses ESP32C5/main/*.c and ESP32C5/components/* directly.
# Board-specific pin assignments and capability flags come from board_hal Kconfig.
set(EXTRA_COMPONENT_DIRS "../ESP32C5/components")

# Add linker flag globally (needed for duplicate symbols in ROM)
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -Wl,-zmuldefs")

# ── Single source of truth for firmware version ──────────────────────────────
set(PROJECT_VER "v2.13.47")

# Bootstrap ESP-IDF build system
include($ENV{IDF_PATH}/tools/cmake/project.cmake)

# Ensure linker option is applied IDF-wide to the final app link
idf_build_set_property(LINK_OPTIONS "-Wl,-zmuldefs" APPEND)

# Make ESP32C5/main headers visible globally (lvgl_memory.h, xpt2046.h, etc.)
idf_build_set_property(COMPILE_OPTIONS "-I${CMAKE_SOURCE_DIR}/../ESP32C5/main" APPEND)

# Suppress warnings-as-errors globally
idf_build_set_property(COMPILE_OPTIONS "-Wno-error" APPEND)

# Expose PROJECT_VER as FW_VERSION compile definition
idf_build_set_property(COMPILE_DEFINITIONS "FW_VERSION=\"${PROJECT_VER}\"" APPEND)

project(CYM-CYD2USB)

# ===== MITM: allow lwIP to forward packets back out the same WiFi interface =====
# Must come AFTER project() — the lwip target is not available until components are registered.
idf_component_get_property(lwip_lib lwip COMPONENT_LIB)
target_compile_definitions(${lwip_lib} PRIVATE IP_FORWARD_ALLOW_TX_ON_RX_NETIF=1)

# ===== POST-BUILD: copy binaries to binaries-cyd2usb every build =====
set(EXPORT_DIR "${CMAKE_SOURCE_DIR}/binaries-cyd2usb")
file(MAKE_DIRECTORY "${EXPORT_DIR}")

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
    COMMAND python -m esptool --chip esp32 merge_bin
            -o "${EXPORT_DIR}/${CMAKE_PROJECT_NAME}-full.bin"
            --flash_mode dio --flash_freq 40m --flash_size 4MB
            0x1000  "${CMAKE_BINARY_DIR}/bootloader/bootloader.bin"
            0x8000  "${CMAKE_BINARY_DIR}/partition_table/partition-table.bin"
            0x10000 "${CMAKE_BINARY_DIR}/${CMAKE_PROJECT_NAME}.bin"
    COMMENT "Copying firmware and generating merged full flash image in ${EXPORT_DIR}"
)
