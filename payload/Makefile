# SPDX-License-Identifier: GPL-3.0-or-later
# Build Stage-1 Loki cave payload directly from a verified Loki device JSON.

DEVICE_JSON   ?= ../devices/mt6789/advan_x1_v5.json
DEVICE_NAME   := $(basename $(notdir $(DEVICE_JSON)))
CROSS_COMPILE ?= aarch64-linux-gnu-
PYTHON        ?= python3

CC      := $(CROSS_COMPILE)gcc
LD      := $(CROSS_COMPILE)ld
OBJCOPY := $(CROSS_COMPILE)objcopy

BUILD_DIR := ../build/payload/$(DEVICE_NAME)

CFLAGS := -nostdlib -ffreestanding -fno-builtin -fno-pie -fno-pic -mcpu=cortex-a76 -O2 \
          -Wall -Wextra -Werror -mgeneral-regs-only -mstrict-align \
          -ffunction-sections -fdata-sections \
          -Iinclude -Icore -I$(BUILD_DIR)

SRCS_C := core/main.c core/tui.c core/lk_provider.c
SRCS_S := arch/arm64/entry.S

OBJS := $(patsubst %.c,$(BUILD_DIR)/%.o,$(SRCS_C)) \
        $(patsubst %.S,$(BUILD_DIR)/%.o,$(SRCS_S))

TARGET_ELF := $(BUILD_DIR)/loki_cave.elf
TARGET_BIN := $(BUILD_DIR)/loki_cave.bin

.PHONY: all clean

all: $(TARGET_BIN)

$(BUILD_DIR)/device_config.h: $(DEVICE_JSON) ../tools/loki-pack.py
	@mkdir -p $(BUILD_DIR)
	@$(PYTHON) ../tools/loki-pack.py --emit-config $(DEVICE_JSON) --out $@

$(BUILD_DIR)/core/%.o: core/%.c $(BUILD_DIR)/device_config.h
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/arch/arm64/%.o: arch/arm64/%.S $(BUILD_DIR)/device_config.h
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/cave.ld: cave.ld $(BUILD_DIR)/device_config.h
	@mkdir -p $(BUILD_DIR)
	$(CC) -E -P -x c -D__LINKER__ -I$(BUILD_DIR) cave.ld -o $@

$(TARGET_ELF): $(OBJS) $(BUILD_DIR)/cave.ld
	$(LD) -T $(BUILD_DIR)/cave.ld --gc-sections -o $@ $(OBJS)

$(TARGET_BIN): $(TARGET_ELF)
	$(OBJCOPY) -O binary $< $@
	@echo "[+] Built Loki Stage-1 cave payload: $@ ($$(wc -c < $@) bytes)"

clean:
	rm -rf ../build/payload
