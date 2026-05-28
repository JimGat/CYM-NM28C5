#!/usr/bin/env python3
"""
Generate a synthetic Schrader-family TPMS packet as a PortaPack .C16 file.

The PortaPack Replay app replays complex baseband IQ samples at a chosen
center frequency.  Set the PortaPack to 315.000 MHz or 433.920 MHz and load
this file to transmit a test TPMS burst that the CYM-NM28C5 TPMS decoder can
receive.

Usage:
    python3 gen_tpms_c16.py [--freq 315|433] [--psi 33.0] [--temp 25] [--id AABBCCDD]
    python3 gen_tpms_c16.py --freq 315 --psi 33.0 --temp 25 --id DEADBEEF

Output: tpms_<freq>MHz_<id>.C16  (load via PortaPack SD → Replay)

Signal parameters (OOK, Schrader EG53MA4 compatible):
  Modulation : OOK / ASK at 315 or 433.92 MHz
  Data rate  : 9,970 baud
  Preamble   : 56 bits 0xAAAAAAAAAAAAAAAA (alternating mark/space)
  Sync word  : 0xD391 (16 bits)
  Payload    : 8 bytes  [ID[4] | pressure[1] | temp[1] | flags[1] | crc8[1]]
  Repetitions: 3 (sensor normally sends 3 identical packets per transmission)
  Sample rate: 500,000 samples/sec  →  put PortaPack Replay at 500k samp/s
"""

import argparse
import struct
import math
import os

SAMPLE_RATE   = 500_000        # Hz — match in PortaPack Replay app
DATA_RATE     = 9_970          # baud
SAMPLES_PER_BIT = SAMPLE_RATE / DATA_RATE   # ~50.15 samples per bit
PREAMBLE_BITS = 56             # 0xAA x 7
SYNC_WORD     = 0xD391         # 16-bit
REPEATS       = 3              # burst count
GAP_BITS      = 80             # silence between bursts
AMP           = 28000          # OOK "on" amplitude (out of 32767)

def crc8(data: bytes) -> int:
    crc = 0
    for byte in data:
        crc ^= byte
        for _ in range(8):
            crc = ((crc << 1) ^ 0x07) & 0xFF if crc & 0x80 else (crc << 1) & 0xFF
    return crc

def bits_from_bytes(data: bytes):
    bits = []
    for byte in data:
        for shift in range(7, -1, -1):
            bits.append((byte >> shift) & 1)
    return bits

def build_packet(sensor_id: int, psi: float, temp_c: int, flags: int = 0) -> bytes:
    raw_pressure = round(psi / 0.36)
    raw_pressure = max(0, min(255, raw_pressure))
    raw_temp     = temp_c + 40
    raw_temp     = max(0, min(255, raw_temp))
    payload = bytes([
        (sensor_id >> 24) & 0xFF,
        (sensor_id >> 16) & 0xFF,
        (sensor_id >>  8) & 0xFF,
         sensor_id        & 0xFF,
        raw_pressure,
        raw_temp,
        flags,
    ])
    crc = crc8(payload)
    pkt = payload + bytes([crc])
    return pkt

def ook_modulate(bits: list, sample_rate: int, data_rate: float) -> list:
    spb = sample_rate / data_rate
    samples = []
    pos = 0.0
    for bit in bits:
        next_pos = pos + spb
        count = round(next_pos) - round(pos)
        amp = AMP if bit else 0
        samples.extend([amp] * count)
        pos = next_pos
    return samples

def build_waveform(bits_list: list) -> list:
    samples = ook_modulate(bits_list, SAMPLE_RATE, DATA_RATE)
    return samples

def to_c16(samples_i: list) -> bytes:
    buf = bytearray()
    for i_val in samples_i:
        i16 = max(-32768, min(32767, int(i_val)))
        buf += struct.pack('<hh', i16, 0)   # Q=0 (pure AM — PortaPack replays I+Q)
    return bytes(buf)

def main():
    ap = argparse.ArgumentParser(description="Generate TPMS .C16 test file for PortaPack")
    ap.add_argument('--freq', type=int, choices=[315, 433], default=315,
                    help="Center frequency MHz (default: 315)")
    ap.add_argument('--psi',  type=float, default=33.0,
                    help="Tire pressure PSI (default: 33.0)")
    ap.add_argument('--temp', type=int,   default=25,
                    help="Temperature °C (default: 25)")
    ap.add_argument('--id',   type=str,   default="DEADBEEF",
                    help="Sensor ID hex (default: DEADBEEF)")
    ap.add_argument('--flags', type=lambda x: int(x,16), default=0,
                    help="Flags byte hex (default: 0x00)")
    args = ap.parse_args()

    sensor_id = int(args.id, 16)
    pkt = build_packet(sensor_id, args.psi, args.temp, args.flags)

    print(f"Sensor ID  : {sensor_id:08X}")
    print(f"Pressure   : {args.psi:.1f} PSI  ({round(args.psi * 6.89476):.0f} kPa)")
    print(f"Temperature: {args.temp}°C")
    print(f"Flags      : 0x{args.flags:02X}")
    print(f"CRC-8      : 0x{pkt[7]:02X}")
    print(f"Raw packet : {' '.join(f'{b:02X}' for b in pkt)}")

    preamble_bits = [int(b) for byte in [0xAA] * (PREAMBLE_BITS // 8) for b in f"{byte:08b}"]
    sync_bits     = [int(b) for b in f"{SYNC_WORD:016b}"]
    data_bits     = bits_from_bytes(pkt)
    gap_bits      = [0] * GAP_BITS

    burst = preamble_bits + sync_bits + data_bits
    full_bits = burst + gap_bits
    full_bits = full_bits * REPEATS

    all_samples = build_waveform(full_bits)

    fname = f"tpms_{args.freq}MHz_{sensor_id:08X}.C16"
    with open(fname, 'wb') as f:
        f.write(to_c16(all_samples))

    duration_ms = len(all_samples) / SAMPLE_RATE * 1000
    print(f"\nWrote      : {fname}")
    print(f"Duration   : {duration_ms:.1f} ms  ({len(all_samples)} samples @ {SAMPLE_RATE//1000}k sps)")
    print(f"\nPortaPack Replay settings:")
    print(f"  Center freq : {args.freq}.000 MHz")
    print(f"  Sample rate : {SAMPLE_RATE//1000}k (500k)")
    print(f"  Gain        : 35+ dB TX")
    print(f"  File        : {fname}")

if __name__ == '__main__':
    main()
