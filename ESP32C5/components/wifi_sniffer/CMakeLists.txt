idf_component_register(
    SRCS "wifi_sniffer.c"
    INCLUDE_DIRS "include" "../wifi_cli/include"
    REQUIRES esp_wifi esp_event esp_timer wifi_scanner led_strip
)

target_compile_options(${COMPONENT_LIB} PRIVATE -Wno-unused-function)

