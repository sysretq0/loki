# SPDX-License-Identifier: GPL-3.0-or-later
# Loki — MediaTek Bootchain Reverse-Engineering & Symbol Mapping Framework

PYTHON ?= python3
LOKI   ?= ./loki

.PHONY: all help test verify proof deadcode devices gen-header clean

all: verify proof deadcode

test: all

help:
	@echo "Loki Build & Verification Targets:"
	@echo "  make               Run full validation suite (verify, proof, deadcode)"
	@echo "  make test          Alias for make all"
	@echo "  make verify        Validate schemas, headers, and firmware consistency"
	@echo "  make proof         Build & verify 164-byte proof hook placement"
	@echo "  make deadcode      Scan hardware strapping & dead-code caves"
	@echo "  make devices       List all mapped device profiles"
	@echo "  make gen-header    Regenerate C header & disasm scripts (pass DEVICE=path/to/device.json)"
	@echo "  make clean         Clean build artifacts and bytecode caches"
	@echo ""
	@echo "Environment overrides:"
	@echo "  FW=/path/to/lk.img Override target firmware container"
	@echo "  DEVICE=devices/... Validate/generate for a specific device"

verify:
	@$(PYTHON) tools/verify.py $(FW)

proof:
	@$(PYTHON) tools/proof/build_proof.py

deadcode:
	@$(PYTHON) tools/capstone/scan_deadcode.py $(FW)

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

