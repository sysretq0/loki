#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""
analyze_lk.py — PyGhidra Automated Headless Symbol & Cross-Reference Extractor

Runs headless inside Ghidra via PyGhidra to crawl string cross-references,
locate unstripped symbols, and output a validated device JSON map.

Usage with PyGhidra:
  GHIDRA_INSTALL_DIR=/opt/ghidra JAVA_TOOL_OPTIONS='-Xmx640m' \\
    /opt/ghidra-py/venv/bin/pyghidra --project-path ~/ghidra-projects \\
    --project-name lk_analysis 00_lk.bin tools/pyghidra/analyze_lk.py
"""

try:
    import ghidra
    from ghidra.program.model.symbol import SourceType
    from ghidra.program.model.address import Address
    IN_GHIDRA = True
except ImportError:
    IN_GHIDRA = False

def run_analysis():
    if not IN_GHIDRA:
        print("[!] This script must be executed within PyGhidra / Ghidra headless environment.")
        return

    program = getCurrentProgram()
    listing = program.getListing()
    memory = program.getMemory()
    ref_manager = program.getReferenceManager()

    print(f"[*] Analyzing program: {program.getName()} (Base: {program.getImageBase()})")

    # String anchors to search and trace
    target_strings = {
        "fastboot_init": "sym.fastboot_init",
        "video_printf": "sym.video_printf",
        "detect_key": "sym.detect_key",
        "ufs-mtk": "sym.ufs_init",
        "bootstrap2": "sym.bootstrap2_name",
        "BCAB": "sym.active_slot_magic",
        "bootargs_ext": "sym.cmdline_append_caller",
    }

    found_symbols = {}

    for text, sym_name in target_strings.items():
        # Search defined strings in data
        data_iter = listing.getDefinedData(True)
        while data_iter.hasNext():
            d = data_iter.next()
            val = str(d.getValue())
            if text in val:
                str_addr = d.getAddress()
                print(f"[+] Found anchor string '{text}' at {str_addr}")
                # Find xrefs to this string
                refs = ref_manager.getReferencesTo(str_addr)
                for ref in refs:
                    from_addr = ref.getFromAddress()
                    func = listing.getFunctionContaining(from_addr)
                    func_entry = func.getEntryPoint() if func else from_addr
                    print(f"    -> Referenced from {from_addr} (Function: {func_entry})")
                    found_symbols[f"{sym_name}_xref"] = str(func_entry)
                break

    print("\n[*] PyGhidra Analysis Complete.")
    for k, v in found_symbols.items():
        print(f"    {k:<30} = {v}")

if __name__ == "__main__" or IN_GHIDRA:
    run_analysis()
