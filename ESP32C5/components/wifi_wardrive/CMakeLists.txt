idf_component_register(
    SRCS "wifi_wardrive.c"
    INCLUDE_DIRS "include" "../wifi_cli/include"
    REQUIRES esp_wifi driver fatfs vfs wifi_scanner led_strip esp_driver_uart
)

target_compile_options(${COMPONENT_LIB} PRIVATE -Wno-unused-function)

