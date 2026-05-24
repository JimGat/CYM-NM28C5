idf_component_register(
    SRCS "src/nrf24.c"
    INCLUDE_DIRS "include"
    REQUIRES
        log
        freertos
        heap
        esp_driver_spi
        esp_driver_gpio
        esp_timer
    PRIV_REQUIRES
        rf_hat
        fatfs
)
