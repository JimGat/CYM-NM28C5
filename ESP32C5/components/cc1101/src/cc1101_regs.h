#pragma once
#include <stdint.h>

// ── CC1101 Register Map ───────────────────────────────────────────────────────

// Configuration registers (R/W, 0x00–0x2E)
#define CC1101_IOCFG2    0x00
#define CC1101_IOCFG1    0x01
#define CC1101_IOCFG0    0x02
#define CC1101_FIFOTHR   0x03
#define CC1101_SYNC1     0x04
#define CC1101_SYNC0     0x05
#define CC1101_PKTLEN    0x06
#define CC1101_PKTCTRL1  0x07
#define CC1101_PKTCTRL0  0x08
#define CC1101_ADDR      0x09
#define CC1101_CHANNR    0x0A
#define CC1101_FSCTRL1   0x0B
#define CC1101_FSCTRL0   0x0C
#define CC1101_FREQ2     0x0D
#define CC1101_FREQ1     0x0E
#define CC1101_FREQ0     0x0F
#define CC1101_MDMCFG4   0x10   // BW + data rate exponent
#define CC1101_MDMCFG3   0x11   // data rate mantissa
#define CC1101_MDMCFG2   0x12   // modulation + sync word
#define CC1101_MDMCFG1   0x13   // preamble + FEC
#define CC1101_MDMCFG0   0x14   // channel spacing
#define CC1101_DEVIATN   0x15
#define CC1101_MCSM2     0x16
#define CC1101_MCSM1     0x17
#define CC1101_MCSM0     0x18
#define CC1101_FOCCFG    0x19
#define CC1101_BSCFG     0x1A
#define CC1101_AGCCTRL2  0x1B
#define CC1101_AGCCTRL1  0x1C
#define CC1101_AGCCTRL0  0x1D
#define CC1101_WOREVT1   0x1E
#define CC1101_WOREVT0   0x1F
#define CC1101_WORCTRL   0x20
#define CC1101_FREND1    0x21
#define CC1101_FREND0    0x22
#define CC1101_FSCAL3    0x23
#define CC1101_FSCAL2    0x24
#define CC1101_FSCAL1    0x25
#define CC1101_FSCAL0    0x26
#define CC1101_RCCTRL1   0x27
#define CC1101_RCCTRL0   0x28
#define CC1101_FSTEST    0x29
#define CC1101_PTEST     0x2A
#define CC1101_AGCTEST   0x2B
#define CC1101_TEST2     0x2C
#define CC1101_TEST1     0x2D
#define CC1101_TEST0     0x2E

// Command strobes (write only, 0x30–0x3D)
#define CC1101_SRES      0x30   // Software reset
#define CC1101_SFSTXON   0x31   // Enable/calibrate FS
#define CC1101_SXOFF     0x32   // Crystal oscillator off
#define CC1101_SCAL      0x33   // Calibrate FS
#define CC1101_SRX       0x34   // Enable RX
#define CC1101_STX       0x35   // Enable TX
#define CC1101_SIDLE     0x36   // IDLE state
#define CC1101_SAFC      0x37   // AFC adjustment
#define CC1101_SWOR      0x38   // Auto RX polling
#define CC1101_SPWD      0x39   // Power down
#define CC1101_SFRX      0x3A   // Flush RX FIFO
#define CC1101_SFTX      0x3B   // Flush TX FIFO
#define CC1101_SWORRST   0x3C   // Reset WOR timer
#define CC1101_SNOP      0x3D   // No-op

// Status registers (burst-read via 0xC0 | addr)
#define CC1101_PARTNUM   0x30   // Part number: 0x00 for CC1101
#define CC1101_VERSION   0x31   // Version: 0x14 for CC1101
#define CC1101_FREQEST   0x32
#define CC1101_LQI       0x33
#define CC1101_RSSI      0x34
#define CC1101_MARCSTATE 0x35
#define CC1101_WORTIME1  0x36
#define CC1101_WORTIME0  0x37
#define CC1101_PKTSTATUS 0x38
#define CC1101_VCO_VC_DAC 0x39
#define CC1101_TXBYTES   0x3A
#define CC1101_RXBYTES   0x3B

// FIFO access addresses
#define CC1101_TXFIFO    0x3F   // Single-byte TX FIFO write
#define CC1101_RXFIFO    0x3F   // Single-byte RX FIFO read
#define CC1101_TXFIFO_BURST 0x7F
#define CC1101_RXFIFO_BURST 0xFF

// SPI access flags
#define CC1101_WRITE     0x00
#define CC1101_READ      0x80
#define CC1101_BURST     0x40

// IOCFG0 values for GDO0 function
#define CC1101_GDO0_RX_DATA      0x0D   // serial data output (async RX)
#define CC1101_GDO0_RX_FIFO      0x01   // high when RX FIFO at/above threshold
#define CC1101_GDO0_PKT_SYNC     0x06   // sync word found
#define CC1101_GDO0_CCA          0x09   // clear channel assessment
#define CC1101_GDO0_CLK_XOSC_1  0x30   // crystal oscillator / 1

// PKTCTRL0 values for packet format
#define CC1101_PKT_NORMAL        0x00
#define CC1101_PKT_SYNC_SERIAL   0x10
#define CC1101_PKT_RAND_TX       0x20
#define CC1101_PKT_ASYNC_SERIAL  0x30   // async serial mode (raw I/O via GDO0)

// MDMCFG2 modulation field (bits 6:4) — register bit patterns
#define CC1101_REG_MOD_2FSK  0x00
#define CC1101_REG_MOD_GFSK  0x10
#define CC1101_REG_MOD_OOK   0x30
#define CC1101_REG_MOD_4FSK  0x40
#define CC1101_REG_MOD_MSK   0x70

// MARCSTATE values
#define CC1101_STATE_SLEEP    0x00
#define CC1101_STATE_IDLE     0x01
#define CC1101_STATE_XOFF     0x02
#define CC1101_STATE_MANCAL   0x05
#define CC1101_STATE_FS_LOCK  0x0A
#define CC1101_STATE_RX       0x0D
#define CC1101_STATE_TX       0x13

// Crystal oscillator frequency (Hz)
#define CC1101_FOSC_HZ  26000000UL

// PA table PATABLE address
#define CC1101_PATABLE  0x3E
