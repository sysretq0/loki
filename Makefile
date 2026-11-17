# SPDX-License-Identifier: GPL-3.0-or-later
# Loki — MediaTek Bootchain Reverse-Engineering & Symbol Mapping Framework

PYTHON ?= python3

.PHONY: all verify proof unpack clean

all: verify proof

verify:
	@$(PYTHON) tools/verify.py

proof:
	@$(PYTHON) tools/proof/build_proof.py

clean:
	@rm -rf build __pycache__ tools/__pycache__ tools/proof/__pycache__
