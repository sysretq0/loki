# Contributing to loki

Thank you for contributing to the open MediaTek Little Kernel function and symbol mapping project!

---

## How to Map a New Device

1. **Extract your device's `lk.img`:**
   ```bash
   python3 tools/unpack.py /path/to/stock/lk.img extracted/
   ```

2. **Run the automated scanners:**
   ```bash
   python3 tools/capstone/scan_lk.py extracted/00_lk.bin
   python3 tools/capstone/scan_bl2_ext.py extracted/03_bl2_ext.bin
   ```

3. **Verify function addresses:**
   * Use Radare2/Rizin (`tools/radare2/lk_map.r2`) or PyGhidra (`tools/pyghidra/analyze_lk.py`) to confirm entry points and cross-references.
   * Refer to [`docs/REVERSE_ENGINEERING_GUIDE.md`](docs/REVERSE_ENGINEERING_GUIDE.md) for detailed function identification recipes.

4. **Create your device definition file:**
   * Path: `devices/<soc_name>/<device_codename>.json` (e.g. `devices/mt6789/advan_x1_v5.json`)
   * Validate against `schema/device.schema.json`.

5. **Submit a Pull Request:**
   * Open a PR with your new `devices/<soc>/<device>.json` file and firmware SHA-256 hash.
   * Include your verification notes and tool outputs in the PR description.
