# SPDX-License-Identifier: GPL-3.0-or-later
# Loki — MediaTek Bootchain Reverse-Engineering & Symbol Mapping Framework

PYTHON ?= python3

.PHONY: all verify proof deadcode unpack clean

all: verify proof deadcode

verify:
	@$(PYTHON) tools/verify.py

proof:
	@$(PYTHON) tools/proof/build_proof.py

deadcode:
	@$(PYTHON) tools/capstone/scan_deadcode.py

clean:
	@rm -rf build __pycache__ tools/__pycache__ tools/proof/__pycache__
