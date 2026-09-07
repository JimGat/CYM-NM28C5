# Host test runner for obs_detectors (no ESP-IDF required).
# obs_store.c guards all ESP-IDF calls behind #ifdef ESP_PLATFORM so plain gcc works.
#
# Usage:
#   make -C ESP32C5/test/obs_detectors        — build and run
#   make -C ESP32C5/test/obs_detectors run    — run only (build if needed)
#   make -C ESP32C5/test/obs_detectors clean  — remove binary

CC      = gcc
CFLAGS  = -std=c11 -Wall -Wextra -O2 \
          -I../../components/obs_store/include \
          -I../../components/obs_detectors/include

SRCS    = test_obs_detectors.c \
          ../../components/obs_store/obs_store.c \
          ../../components/obs_detectors/obs_detectors.c

TARGET  = test_obs_detectors

.PHONY: all run clean

all: $(TARGET)
	./$(TARGET)

run: $(TARGET)
	./$(TARGET)

$(TARGET): $(SRCS)
	$(CC) $(CFLAGS) $^ -o $@

clean:
	rm -f $(TARGET)
