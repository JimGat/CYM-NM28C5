if("${IDF_VERSION_MAJOR}.${IDF_VERSION_MINOR}" VERSION_GREATER_EQUAL "5.5")
    set(PRIV_REQ esp_driver_gpio esp_driver_i2c)
else()
    set(PRIV_REQ driver)
endif()

idf_component_register(SRCS "esp_lcd_touch_cst3530.c" INCLUDE_DIRS "include" REQUIRES "esp_lcd" PRIV_REQUIRES ${PRIV_REQ})
