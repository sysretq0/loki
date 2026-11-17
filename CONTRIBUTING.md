# Contributing to loki

Thank you for contributing to the open MediaTek Little Kernel function and symbol mapping project!

`loki` provides a unified command-line tool (`./loki`) and automated scaffolding to make mapping a new device as fast and frictionless as possible.

---

## Prerequisites

Install core dependencies (Python 3.8+):
```bash
pip install -r requirements.txt
```

---

## 3-Step Guide to Adding a New Device

### 1. Scaffold Your Device Profile Automatically
Run `./loki init` with your device codename, SoC, and stock `lk.img`:
```bash
./loki init <device_codename> <soc_name> /path/to/stock/lk.img
# Example:
./loki init redmi_note_12 mt6789 /path/to/stock/lk.img
```
This automatically:
* Unpacks and identifies all subpartitions (`lk`, `bl2_ext`, `aee`, `dtb`, certificates).
* Computes exact container offsets, payload sizes, and container spans.
* Detects in-memory `.text` zero-filled alignment regions (`ZERO_REGION_1`..`3`).
* Calculates trailing unallocated container flash space.
* Scaffolds `devices/<soc>/<device_codename>.json` and auto-generates matching `devices/<soc>/<device_codename>.h`.

### 2. Discover & Verify Function Entry Points
Unpack the container to get discrete raw binaries:
```bash
./loki unpack /path/to/stock/lk.img extracted/
```

Run the automated discovery scanners:
```bash
./loki scan extracted/00_lk.bin
./loki scan-bl2 extracted/03_bl2_ext.bin
./loki deadcode extracted/00_lk.bin
```

Confirm addresses with Ghidra or radare2:
* Refer to [`docs/REVERSE_ENGINEERING_GUIDE.md`](docs/REVERSE_ENGINEERING_GUIDE.md) for identification recipes.
* Use `tools/radare2/lk_map.r2` or `tools/pyghidra/analyze_lk.py`.

Update your `devices/<soc>/<device_codename>.json` with discovered symbols, then regenerate the C header:
```bash
./loki gen-header devices/<soc>/<device_codename>.json
```

### 3. Validate Consistency & Open a PR
Run the consistency verification suite:
```bash
./loki verify devices/<soc>/<device_codename>.json -f /path/to/stock/lk.img
```
Ensure all schema checks, bi-directional header checks, and binary assertions pass.

Submit your Pull Request with:
* `devices/<soc>/<device_codename>.json`
* `devices/<soc>/<device_codename>.h`
* Verification notes and firmware container SHA-256 in the PR description.
