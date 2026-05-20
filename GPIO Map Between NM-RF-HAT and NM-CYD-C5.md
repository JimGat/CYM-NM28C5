GPIO Mapping between the FPC connector on the NM-RF-Hat and the NM-CYD-C5 here is the table.  When you see the GPIO on the board schematics this 
is the actual NM-CYD-C5 GPIO  The board uses I2C where needed and then for the devices that use SPI it uses pin 27 on the RF-HAT Pin 9 on the CYD-C5 to be the chip select.
The dip switches toggle power to the module.  That is why there is a conflict if any two modules are on.  Some are I2C and some are SPI and they leave a dedicated CS for the
SD card.  That way the SD is always avalalble.


NM-RF-HAT Label |  FPC1 Pin# |  NM-CYD-C5 GPIO
OI19            |      1     |  GPIO2 SPI MISO
IO18            |      2     |  GPIO6 SPI CLK
IO23            |      3     |  CPIO7 SPI MOSI
IO5             |      4     |  GPIO10 SPI CS for TFT {SD}
GND             |      5     |  GND
IO21            |      6     |  GPIO4 LP_RX {not connected to uart passthrough)
IO22            |      7     |  GPIO8 SCL (sometimes used for CS when not used for I2C}
IO35            |      8     |  GPIO5 LP_TX {not connected to uart passthrough)
IO27            |      9     |  GPIO9 SDA
USB D-          |      10    |  USB D-
USB D+          |      11    |  USB D+
GND             |      12    |  GND
GND             |      13    |  GND
GND             |      14    |  GND


