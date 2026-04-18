cmake_minimum_required(VERSION 3.16)

# Add linker flag globally (needed for duplicate symbols in ROM)
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -Wl,-zmuldefs")

# Bootstrap ESP-IDF build system
include($ENV{IDF_PATH}/tools/cmake/project.cmake)

# Ensure linker option is applied IDF-wide to the final app link
idf_build_set_property(LINK_OPTIONS "-Wl,-zmuldefs" APPEND)

# Make 'main' headers (e.g., lvgl_memory.h) visible globally for components that include by name
idf_build_set_property(COMPILE_OPTIONS "-I${CMAKE_SOURCE_DIR}/main" APPEND)

project(CYM-NM28C5)

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
    COMMENT "Copying firmware to ${EXPORT_DIR}"
)
