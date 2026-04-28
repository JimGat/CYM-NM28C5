idf_component_register(SRCS "attack_handshake.c" "xpt2046.c" "lvgl_memory.c" "main.c" "dexter_img.c" "lv_extra_symbols.c" "lab_bg.c" "deedee_img.c" "bt_lookout.c" INCLUDE_DIRS . REQUIRES heap driver esp_event console bt esp_adc esp-tls PRIV_REQUIRES wifi_attacks wifi_cli wifi_scanner wifi_sniffer wifi_wardrive sniffer frame_analyzer hccapx_serializer pcap_serializer)

# Disable format warning errors for ESP32-C5 (size_t is unsigned int, not long unsigned int)
target_compile_options(${COMPONENT_LIB} PRIVATE -Wno-error=format)
