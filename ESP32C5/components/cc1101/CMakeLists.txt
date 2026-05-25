idf_component_register(
    SRCS "src/cc1101.c"
    INCLUDE_DIRS "include" "src"
    REQUIRES
        log
        freertos
        heap
        esp_driver_spi
        esp_driver_gpio
        esp_timer
    PRIV_REQUIRES
        rf_hat
)
