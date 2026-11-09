import os
import sys
import json
import glob
import zipfile
import urllib.request
import rzpipe

# ── Argument Parsing ────────────────────────────────────────────────────────
if len(sys.argv) < 3:
    print("Usage: python main.py <path_to_binary.exe> <output_file.c>")
    sys.exit(1)

BINARY_PATH = sys.argv[1]
OUTPUT_FILE = sys.argv[2]

# ── Auto-Detection & Self-Installation ──────────────────────────────────────
# Common common local folder next to the script or system paths
LOCAL_CUTTER_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "Cutter-v2.5.0-Windows-x86_64")
POSSIBLE_DIRS = [
    LOCAL_CUTTER_DIR,
    r"H:\Cutter-v2.4.1-Windows-x86_64",
    r"C:\Program Files\Cutter"
]

CUTTER_DIR = None
for d in POSSIBLE_DIRS:
    if os.path.exists(os.path.join(d, "rizin.exe")):
        CUTTER_DIR = d
        break

# If Cutter is missing entirely, download and extract it automatically
if not CUTTER_DIR:
    print("[*] Cutter/Rizin not found locally.")
    print("[*] Automatically downloading Cutter v2.5.0 from GitHub (this may take a moment)...")
    
    zip_url = "https://github.com/rizinorg/cutter/releases/download/v2.5.0/Cutter-v2.5.0-Windows-x86_64.zip"
    zip_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "cutter.zip")
    
    try:
        # Download with a simple progress report block
        def reporthook(blocknum, blocksize, totalsize):
            readsofar = blocknum * blocksize
            if totalsize > 0:
                percent = readsofar * 1e2 / totalsize
                sys.stdout.write(f"\r[*] Downloading... {percent:.2f}% ({readsofar / (1024*1024):.1f} MB)")
                sys.stdout.flush()
            else:
                sys.stdout.write(f"\r[*] Read {readsofar} bytes")
                sys.stdout.flush()

        urllib.request.urlretrieve(zip_url, zip_path, reporthook)
        print("\n[*] Download complete. Extracting archive...")
        
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            zip_ref.extractall(os.path.dirname(os.path.abspath(__file__)))
            
        # Clean up the downloaded zip file to save space
        if os.path.exists(zip_path):
            os.remove(zip_path)
            
        CUTTER_DIR = LOCAL_CUTTER_DIR
        print(f"[+] Cutter successfully installed to: {CUTTER_DIR}")
        
    except Exception as e:
        print(f"\n[!] Error auto-downloading Cutter: {e}")
        print("[!] Please check your internet connection or download Cutter manually.")
        sys.exit(1)

print(f"[*] Using Cutter directory: {CUTTER_DIR}")

# ── Locate rz-ghidra pieces inside the Cutter folder ─────────────────────────
def find_first(pattern):
    hits = glob.glob(os.path.join(CUTTER_DIR, "**", pattern), recursive=True)
    return hits[0] if hits else None

plugin_dll = find_first("core_ghidra*.dll") or find_first("rz_ghidra*.dll")
sla_file   = find_first("x86-64.sla")
ldefs_file = find_first("x86.ldefs")

sleigh_home = None
if sla_file:
    sleigh_home = os.path.dirname(sla_file)
elif ldefs_file:
    sleigh_home = os.path.dirname(ldefs_file)

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

plugins = r.cmd("Lc")
ghidra_ok = "ghidra" in plugins.lower() and "pdg" in r.cmd("pdg?")
decompile_cmd = "pdg" if ghidra_ok else "pdf"
print(f"[*] Decompiler command: {decompile_cmd}")

# ── Analysis ─────────────────────────────────────────────────────────────────
print("[*] Running analysis (aaa)...")
r.cmd("aaa")
set_sleigh()

raw = r.cmd("aflj")
try:
    functions = json.loads(raw) if raw and raw.strip() else []
except json.JSONDecodeError:
    functions = []

if not functions:
    print("[!] No functions found. The binary may be packed/obfuscated.")
    r.quit()
    sys.exit(1)

print(f"[*] Found {len(functions)} functions. Dumping to C...")

def run(cmd_name, addr_hex):
    return r.cmd(f"s {addr_hex}; {cmd_name}")

BAD_STRINGS = ["No sleigh specification", "Cannot find", "Unknown command", "does not exist", "Invalid"]
def is_bad(code):
    return (not code) or (not code.strip()) or any(b in code for b in BAD_STRINGS)

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
        except Exception:
            errors += 1
            continue

        if is_bad(code):
            errors += 1
            continue

        f.write(f"// {'=' * 70}\n// Function : {name}\n// Address  : {addr_hex}\n// {'=' * 70}\n")
        f.write(code.strip() + "\n\n")
        success += 1

r.quit()

print("\n[+] Done!")
print(f"    Decompiled : {success}")
print(f"    Skipped    : {skipped} (import stubs)")
print(f"    Errors     : {errors}")
print(f"    Output     : {OUTPUT_FILE}")
