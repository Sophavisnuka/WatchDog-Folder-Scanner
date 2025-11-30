import os
import json
import hashlib
import shutil
from pathlib import Path
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import getpass
import time

QUARANTINE_FOLDER = "quarantine"
BAD_HASHES_FILE = "bad_hashes.json"
SCAN_EXTENSIONS = [".exe", ".dll", ".txt", ".json", ".bat", ".cmd"]

# ------------------------------
# Load known malicious hashes
# ------------------------------
if os.path.exists(BAD_HASHES_FILE):
    with open(BAD_HASHES_FILE, "r") as f:
        BAD_HASHES = json.load(f).get("sha256", [])
else:
    BAD_HASHES = []


# ------------------------------
# Hashing
# ------------------------------
def sha256_file(path: Path) -> str:
    sha = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            for block in iter(lambda: f.read(4096), b""):
                sha.update(block)
    except:
        return ""
    return sha.hexdigest()


# ------------------------------
# Pattern detection
# ------------------------------
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

    return any(p in content.lower() for p in patterns)


# ------------------------------
# Heuristics
# ------------------------------
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


# ------------------------------
# Quarantine
# ------------------------------
def move_to_quarantine(path: Path):
    os.makedirs(QUARANTINE_FOLDER, exist_ok=True)
    target = Path(QUARANTINE_FOLDER) / path.name

    counter = 1
    while target.exists():
        target = Path(QUARANTINE_FOLDER) / f"{path.stem}_{counter}{path.suffix}"
        counter += 1

    shutil.move(str(path), str(target))


# ------------------------------
# Analyze incoming file
# ------------------------------
def analyze_file(path: Path):
    if not path.exists():
        return

    if path.suffix.lower() not in SCAN_EXTENSIONS:
        return

    file_hash = sha256_file(path)
    if file_hash in BAD_HASHES:
        move_to_quarantine(path)
        return

    if contains_suspicious_patterns(path):
        move_to_quarantine(path)
        return

    score = heuristic_score(path)
    if score >= 2:
        move_to_quarantine(path)


# ------------------------------
# Real-time event handler
# ------------------------------
class WatchDogHandler(FileSystemEventHandler):
    def on_created(self, event):
        if not event.is_directory:
            analyze_file(Path(event.src_path))

    def on_modified(self, event):
        if not event.is_directory:
            analyze_file(Path(event.src_path))


# ------------------------------
# Start real-time background watcher
# ------------------------------
def start_background_watcher():
    username = getpass.getuser()
    base = f"C:/Users/{username}"

    watch_dirs = [
        Path(base + "/Downloads"),
        Path(base + "/Desktop"),
        Path(base + "/Documents"),
        Path(base + "/AppData/Local/Temp")
    ]

    observer = Observer()
    handler = WatchDogHandler()

    for folder in watch_dirs:
        if folder.exists():
            observer.schedule(handler, str(folder), recursive=True)

    observer.start()

    try:
        while True:
            time.sleep(1)
    except:
        observer.stop()

    observer.join()


# ------------------------------
# Entry point
# ------------------------------
if __name__ == "__main__":
    start_background_watcher()
