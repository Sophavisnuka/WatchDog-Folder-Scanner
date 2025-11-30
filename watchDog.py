import os
import json
import hashlib
import shutil
from pathlib import Path
import getpass

# ============================================
# Configuration
# ============================================
QUARANTINE_FOLDER = "quarantine"
BAD_HASHES_FILE = "bad_hashes.json"

SCAN_EXTENSIONS = [".exe", ".dll", ".txt", ".json", ".bat", ".cmd"]

# ============================================
# Load known malicious hashes
# ============================================
if os.path.exists(BAD_HASHES_FILE):
    with open(BAD_HASHES_FILE, "r") as f:
        BAD_HASHES = json.load(f).get("sha256", [])
else:
    BAD_HASHES = []


# ============================================
# SHA256 file hashing
# ============================================
def sha256_file(path: Path) -> str:
    sha = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            for block in iter(lambda: f.read(4096), b""):
                sha.update(block)
    except:
        return ""
    return sha.hexdigest()


# ============================================
# Suspicious pattern detection inside text files
# ============================================
def contains_suspicious_patterns(path: Path) -> bool:
    if path.suffix not in [".txt", ".json", ".bat", ".cmd"]:
        return False

    try:
        content = path.read_text(errors="ignore")
    except:
        return False

    patterns = [
        "powershell",
        "cmd /c",
        "invoke-webrequest",
        "wget ",
        "http://",
        "https://",
        "<script>",
        "eval(",
        "base64"
    ]

    for p in patterns:
        if p in content.lower():
            return True

    return False


# ============================================
# Heuristic detection (abnormal behavior)
# ============================================
def heuristic_score(path: Path) -> int:
    score = 0
    size = path.stat().st_size

    if path.suffix == ".exe" and size < 20_000:
        score += 2

    if path.suffix == ".exe" and size > 200_000_000:
        score += 1

    if path.suffix in [".txt", ".json"]:
        try:
            path.read_text()
        except:
            score += 2

    return score


# ============================================
# Move suspicious file to quarantine
# ============================================
def move_to_quarantine(path: Path):
    os.makedirs(QUARANTINE_FOLDER, exist_ok=True)
    target = Path(QUARANTINE_FOLDER) / path.name

    counter = 1
    while target.exists():
        target = Path(QUARANTINE_FOLDER) / f"{path.stem}_{counter}{path.suffix}"
        counter += 1

    shutil.move(str(path), str(target))
    print(f"🚨 [QUARANTINE] {path.name} → {target}")


# ============================================
# Folder scanning logic
# ============================================
def scan_folder(folder: Path):
    if not folder.exists():
        return

    print(f"\n🔍 Scanning: {folder}")

    for file in folder.rglob("*"):
        if not file.is_file():
            continue

        if file.suffix.lower() not in SCAN_EXTENSIONS:
            continue

        print(f"→ Checking: {file.name}")

        file_hash = sha256_file(file)
        if file_hash in BAD_HASHES:
            print("❗ BAD HASH MATCH — known malicious!")
            move_to_quarantine(file)
            continue

        if contains_suspicious_patterns(file):
            print("⚠ Suspicious patterns detected!")
            move_to_quarantine(file)
            continue

        score = heuristic_score(file)
        if score >= 2:
            print(f"⚠ Heuristic Score {score} — abnormal file!")
            move_to_quarantine(file)
            continue

        print("✔ Clean")


# ============================================
# Auto-scan common malware locations
# ============================================
def auto_scan_common_locations():
    username = getpass.getuser()
    base = f"C:/Users/{username}"

    folders = [
        Path(base + "/Downloads"),
        Path(base + "/Desktop"),
        Path(base + "/Documents"),
        Path(base + "/AppData/Local/Temp"),
    ]

    print("===== AUTO-SCAN MODE =====")
    print("Scanning common locations (Downloads, Desktop, Documents, Temp)...")

    for folder in folders:
        scan_folder(folder)

    print("\n✅ Auto-scan complete!")


# ============================================
# Program Entry
# ============================================
if __name__ == "__main__":
    print("===== WatchDog Lite Scanner =====")
    print("1. Auto-scan common folders")
    print("2. Scan manually (enter folder path)")
    print("3. Exit")

    choice = input("\nSelect option: ")

    if choice == "1":
        auto_scan_common_locations()

    elif choice == "2":
        path = input("Enter folder path: ")
        scan_folder(Path(path))

    else:
        print("Exiting...")
