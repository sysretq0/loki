# SPDX-License-Identifier: GPL-3.0-or-later
# Loki — MediaTek Bootchain Reverse-Engineering & Symbol Mapping Framework

PYTHON ?= python3
LOKI   ?= ./loki

.PHONY: all help test verify proof payload pack deadcode scan-atf scan-pl devices gen-header clean

all: verify proof deadcode

test: all

help:
	@echo "Loki Build & Verification Targets:"
	@echo "  make               Run full validation suite (verify, proof, deadcode)"
	@echo "  make test          Alias for make all"
	@echo "  make verify        Validate schemas, headers, and firmware consistency"
	@echo "  make proof         Build & verify 164-byte proof hook placement"
	@echo "  make payload       Build Stage-1 LK cave payload (pass DEVICE=...)"
	@echo "  make pack          Pack verified lk_loki.img with embedded subpartition (FW=..., PAYLOAD=...)"
	@echo "  make deadcode      Scan hardware strapping & dead-code caves"
	@echo "  make scan-atf      Scan ARM Trusted Firmware (BL31) vectors & SMCs"
	@echo "  make scan-pl       Scan MediaTek Preloader (BL2) GFH & USBDL loop"
	@echo "  make devices       List all mapped device profiles"
	@echo "  make gen-header    Regenerate C header & disasm scripts (pass DEVICE=path/to/device.json)"
	@echo "  make clean         Clean build artifacts and bytecode caches"
	@echo ""
	@echo "Environment overrides:"
	@echo "  FW=/path/to/img    Override target firmware container (lk.img, tee.img, or preloader.img)"
	@echo "  DEVICE=devices/... Validate/generate for a specific device"

verify:
	@$(PYTHON) tools/verify.py $(FW)

proof:
	@$(PYTHON) tools/proof/build_proof.py

payload:
	@$(MAKE) -C payload DEVICE_JSON=$(if $(DEVICE),$(abspath $(DEVICE)),$(abspath devices/mt6789/advan_x1_v5.json)) all

pack:
	@if [ -z "$(FW)" ] || [ -z "$(PAYLOAD)" ]; then \
		echo "Usage: make pack FW=/path/to/stock/lk.img PAYLOAD=/path/to/u-boot.bin [DEVICE=devices/mt6789/advan_x1_v5.json] [OUT=build/lk_loki.img]"; \
		exit 1; \
	fi
	@$(PYTHON) loki pack $(if $(DEVICE),$(DEVICE),devices/mt6789/advan_x1_v5.json) --lk $(FW) --payload $(PAYLOAD) -o $(if $(OUT),$(OUT),build/lk_loki.img)

deadcode:
	@$(PYTHON) tools/capstone/scan_deadcode.py $(FW)

scan-atf:
	@$(PYTHON) tools/capstone/scan_atf.py $(FW)

scan-pl:
	@$(PYTHON) tools/capstone/scan_preloader.py $(FW)

devices:
	@$(PYTHON) loki devices

gen-header:
	@if [ -z "$(DEVICE)" ]; then \
		echo "Usage: make gen-header DEVICE=devices/mt6789/advan_x1_v5.json"; \
		exit 1; \
	fi
	@$(PYTHON) tools/gen_header.py $(DEVICE) --all

clean:
	@rm -rf build extracted __pycache__ tools/__pycache__ tools/proof/__pycache__ tools/capstone/__pycache__ tools/pyghidra/__pycache__

