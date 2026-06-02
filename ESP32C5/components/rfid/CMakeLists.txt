idf_component_register(
    SRCS
        "src/rfid_types.c"
        "src/rfid_manager.c"
        "src/rfid_storage.c"
        "src/flipper_nfc_file.c"
        "src/flipper_lf_file.c"
        "src/hf/pn532_driver.c"
        "src/hf/pn532_reader.c"
        "src/hf/pn532_target.c"
        "src/hf/mifare_classic.c"
        "src/hf/ntag.c"
        "src/lf/lf_stub.c"
    INCLUDE_DIRS "include"
    REQUIRES
        rf_hat
        nvs_flash
        freertos
        log
        fatfs
    PRIV_REQUIRES
        esp_driver_i2c
        esp_driver_gpio
        esp_timer
        esp_system
)

# rfid_storage.c snprintf bounds can't be statically resolved for FAT filenames
target_compile_options(${COMPONENT_LIB} PRIVATE -Wno-error=format-truncation)
