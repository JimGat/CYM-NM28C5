idf_component_register(
    SRCS
        "src/rf_hat_config.c"
        "src/ir_hat.c"
        "src/rf433_hat.c"
        "src/radio_hat.c"
        "src/rfid_hat.c"
    INCLUDE_DIRS "include"
    REQUIRES
        nvs_flash
        esp_timer
        freertos
        log
    PRIV_REQUIRES
        esp_driver_rmt
        esp_driver_gpio
        fatfs
)
