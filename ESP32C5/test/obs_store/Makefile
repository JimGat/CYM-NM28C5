# Host unit tests for obs_store — plain gcc, no ESP-IDF required.
# Usage: make            — build and run
#        make run        — run only (build if needed)
#        make clean      — remove build artefacts

CC      := gcc
CFLAGS  := -std=c11 -Wall -Wextra -Wpedantic -O2 \
           -I../../components/obs_store/include

SRC_IMPL := ../../components/obs_store/obs_store.c
SRC_TEST := test_obs_record.c
OUT      := test_obs_store

.PHONY: all run clean

all: $(OUT)
	./$(OUT)

run: $(OUT)
	./$(OUT)

$(OUT): $(SRC_IMPL) $(SRC_TEST)
	$(CC) $(CFLAGS) -o $@ $^

clean:
	rm -f $(OUT)
