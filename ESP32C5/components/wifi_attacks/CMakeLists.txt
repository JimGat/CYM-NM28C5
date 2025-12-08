idf_component_register(
    SRCS "wifi_attacks.c"
    INCLUDE_DIRS "include" "../wifi_cli/include"
    REQUIRES esp_wifi esp_event esp_http_server lwip mbedtls wifi_scanner wifi_wardrive led_strip
)

target_compile_options(${COMPONENT_LIB} PRIVATE -Wno-unused-function)

# Ensure this component participates in app link with -zmuldefs as well
target_link_options(${COMPONENT_LIB} PRIVATE -Wl,-zmuldefs)
