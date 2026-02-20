CC      = gcc
CFLAGS  = -O3 -march=native -funroll-loops -Wall -Wextra -std=c99
LDFLAGS = -lm

SRC_DIR   = c
BUILD_DIR = build

HASH_SRC  = $(SRC_DIR)/meow_hash_v7.c
MAIN_SRC  = $(SRC_DIR)/main.c
HEADER    = $(SRC_DIR)/meow_hash_v7.h

CLI_BIN   = meowhash256
SHARED    = libmeowhash256.so

.PHONY: all clean lib cli

all: cli lib

cli: $(BUILD_DIR)/$(CLI_BIN)

lib: $(BUILD_DIR)/$(SHARED)

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(BUILD_DIR)/$(CLI_BIN): $(MAIN_SRC) $(HASH_SRC) $(HEADER) | $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ $(MAIN_SRC) $(HASH_SRC) $(LDFLAGS)

$(BUILD_DIR)/$(SHARED): $(HASH_SRC) $(HEADER) | $(BUILD_DIR)
	$(CC) $(CFLAGS) -shared -fPIC -o $@ $(HASH_SRC) $(LDFLAGS)

clean:
	rm -rf $(BUILD_DIR)
