idf_component_register(
    SRCS "wifi_common.c" "wifi_cli.c"
    INCLUDE_DIRS "include"
    REQUIRES esp_wifi nvs_flash esp_event esp_netif console led_strip wifi_scanner wifi_sniffer wifi_attacks wifi_wardrive
)

