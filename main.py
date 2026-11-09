import os
import sys
import json
import glob
import rzpipe

# ── Argument Parsing ────────────────────────────────────────────────────────
if len(sys.argv) < 3:
    print("Usage: python main.py <path_to_binary.exe> <output_file.c>")
    sys.exit(1)

BINARY_PATH = sys.argv[1]
OUTPUT_FILE = sys.argv[2]

# ── Paths ────────────────────────────────────────────────────────────────────
CUTTER_DIR  = r"H:\Cutter-v2.4.1-Windows-x86_64"

# ── Locate rz-ghidra pieces inside the Cutter folder ─────────────────────────
def find_first(pattern):
    hits = glob.glob(os.path.join(CUTTER_DIR, "**", pattern), recursive=True)
    return hits[0] if hits else None

plugin_dll = find_first("core_ghidra*.dll") or find_first("rz_ghidra*.dll")
sla_file   = find_first("x86-64.sla")
ldefs_file = find_first("x86.ldefs")

print(f"[*] rz-ghidra plugin : {plugin_dll}")
print(f"[*] x86-64.sla       : {sla_file}")
print(f"[*] x86.ldefs        : {ldefs_file}")

# Sleigh home = the folder that holds the .sla / .ldefs files
sleigh_home = None
if sla_file:
    sleigh_home = os.path.dirname(sla_file)
elif ldefs_file:
    sleigh_home = os.path.dirname(ldefs_file)
print(f"[*] Sleigh home      : {sleigh_home}")

# ── Environment ──────────────────────────────────────────────────────────────
os.environ["PATH"] = CUTTER_DIR + os.pathsep + os.environ.get("PATH", "")
if plugin_dll:
    os.environ["RZ_USER_PLUGINS"] = os.path.dirname(plugin_dll)
    os.environ["RZ_PLUGIN_PATH"]  = os.path.dirname(plugin_dll)

# ── Open binary ──────────────────────────────────────────────────────────────
print(f"[*] Opening target binary: {BINARY_PATH}")
print("[*] Launching rizin via rzpipe...")
r = rzpipe.open(BINARY_PATH)

def set_sleigh():
    if sleigh_home:
        r.cmd(f"e ghidra.sleighhome={sleigh_home}")

set_sleigh()
print("[*] sleighhome now   :", r.cmd("e ghidra.sleighhome").strip())

plugins = r.cmd("Lc")
ghidra_ok = "ghidra" in plugins.lower() and "pdg" in r.cmd("pdg?")
decompile_cmd = "pdg" if ghidra_ok else "pdf"
print(f"[*] Decompiler command: {decompile_cmd}"
      + ("" if ghidra_ok else "  (rz-ghidra NOT loaded -> disassembly only)"))

# ── Analysis ─────────────────────────────────────────────────────────────────
print("[*] Running analysis (aaa) — this may take a while...")
r.cmd("aaa")
set_sleigh()   # set again after analysis, in case it was reset

raw = r.cmd("aflj")
try:
    functions = json.loads(raw) if raw and raw.strip() else []
except json.JSONDecodeError:
    functions = []

if not functions:
    print("[!] No functions found. The binary may be packed/obfuscated.")
    r.quit()
    sys.exit(1)

print(f"[*] Found {len(functions)} functions.")

def run(cmd_name, addr_hex):
    return r.cmd(f"s {addr_hex}; {cmd_name}")

BAD_STRINGS = ["No sleigh specification", "Cannot find", "Unknown command",
               "does not exist", "Invalid"]

def is_bad(code):
    return (not code) or (not code.strip()) or any(b in code for b in BAD_STRINGS)

# ── Sanity test on the biggest real function ─────────────────────────────────
candidates = [f for f in functions if not f.get("name", "").startswith(("sym.imp.", "imp."))]
if candidates:
    test = max(candidates, key=lambda f: f.get("size", 0))
    test_out = run(decompile_cmd, hex(test["offset"]))
    print(f"[*] Test decompile of {test['name']}: {len(test_out)} chars")

    if is_bad(test_out) and decompile_cmd == "pdg":
        print("[!] pdg test FAILED. Raw output was:", repr(test_out[:300]))
        print("[!] Check the '.sla' / 'Sleigh home' lines printed at the top.")
        print("[*] Falling back to pdf (disassembly only)...")
        decompile_cmd = "pdf"

# ── Decompile and dump ───────────────────────────────────────────────────────
success = skipped = errors = 0

with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
    f.write(f"// Auto-generated with '{decompile_cmd}'\n\n")

    for i, fn in enumerate(functions, 1):
        name = fn.get("name", "unknown")
        if name.startswith(("sym.imp.", "imp.")):
            skipped += 1
            continue

        addr_hex = hex(fn.get("offset", 0))
        try:
            code = run(decompile_cmd, addr_hex)
        except Exception as e:
            print(f"  [!] Exception on {name} @ {addr_hex}: {e}")
            errors += 1
            continue

        if is_bad(code):
            if errors < 5:
                print(f"  [!] {name} @ {addr_hex}: {code.strip()[:120]!r}")
            errors += 1
            continue

        f.write(f"// {'=' * 70}\n// Function : {name}\n// Address  : {addr_hex}\n// {'=' * 70}\n")
        f.write(code.strip() + "\n\n")
        success += 1

        if i % 50 == 0:
            print(f"  ... {i}/{len(functions)}")

r.quit()

print("\n[+] Done!")
print(f"    Decompiled : {success}")
print(f"    Skipped    : {skipped}  (import stubs)")
print(f"    Errors     : {errors}")
print(f"    Output     : {OUTPUT_FILE}")