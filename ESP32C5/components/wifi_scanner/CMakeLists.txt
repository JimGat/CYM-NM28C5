idf_component_register(
    SRCS "wifi_scanner.c"
    INCLUDE_DIRS "include" "../wifi_cli/include"
    REQUIRES esp_wifi esp_event nvs_flash led_strip esp_timer
)

