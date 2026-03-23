#!/usr/bin/env python3
from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
from pathlib import Path


BOOTLOADER_OFFSET = "0x2000"
PARTITION_OFFSET = "0x8000"
APP_OFFSET = "0x10000"
FLASH_MODE = "dio"
FLASH_FREQ = "80m"
FLASH_SIZE = "8MB"


def pick_first(base_dir: Path, names: list[str]) -> Path | None:
    for name in names:
        candidate = base_dir / name
        if candidate.exists():
            return candidate
    return None


def default_files(base_dir: Path) -> tuple[Path, Path, Path]:
    bootloader = pick_first(base_dir, ["bootloader.bin", "bootloader-esp32c5.bin"])
    partition = pick_first(base_dir, ["partition-table.bin", "partition-table-esp32c5.bin"])
    firmware = pick_first(base_dir, ["pancake-esp32c5.bin", "projectZero.bin"])

    missing = []
    if bootloader is None:
        missing.append("bootloader.bin")
    if partition is None:
        missing.append("partition-table.bin")
    if firmware is None:
        missing.append("pancake-esp32c5.bin or projectZero.bin")
    if missing:
        raise FileNotFoundError(f"Missing required files next to flash_board.py: {', '.join(missing)}")

    return bootloader, partition, firmware


def run_esptool(args: list[str]) -> int:
    if shutil.which("esptool.py"):
        cmd = ["esptool.py", *args]
    else:
        cmd = [sys.executable, "-m", "esptool", *args]

    try:
        return subprocess.call(cmd)
    except FileNotFoundError:
        print("esptool is not installed. Run: python -m pip install esptool", file=sys.stderr)
        return 1


def main() -> int:
    script_dir = Path(__file__).resolve().parent
    default_bootloader, default_partition, default_firmware = default_files(script_dir)

    parser = argparse.ArgumentParser(
        description="Flash the ESP32-C5 firmware bundle produced by GitHub Actions."
    )
    parser.add_argument("--port", required=True, help="Serial port, for example COM5 or /dev/ttyUSB0")
    parser.add_argument("--baud", default="921600", help="Flash baud rate")
    parser.add_argument("--bootloader", default=str(default_bootloader), help="Path to bootloader binary")
    parser.add_argument("--partition-table", default=str(default_partition), help="Path to partition table binary")
    parser.add_argument("--firmware", default=str(default_firmware), help="Path to app firmware binary")
    parser.add_argument("--erase-first", action="store_true", help="Erase flash before writing")
    args = parser.parse_args()

    if args.erase_first:
        erase_rc = run_esptool(["--chip", "esp32c5", "--port", args.port, "erase_flash"])
        if erase_rc != 0:
            return erase_rc

    return run_esptool(
        [
            "--chip",
            "esp32c5",
            "--port",
            args.port,
            "--baud",
            args.baud,
            "--before",
            "default_reset",
            "--after",
            "hard_reset",
            "write_flash",
            "--flash_mode",
            FLASH_MODE,
            "--flash_freq",
            FLASH_FREQ,
            "--flash_size",
            FLASH_SIZE,
            BOOTLOADER_OFFSET,
            args.bootloader,
            PARTITION_OFFSET,
            args.partition_table,
            APP_OFFSET,
            args.firmware,
        ]
    )


if __name__ == "__main__":
    raise SystemExit(main())
