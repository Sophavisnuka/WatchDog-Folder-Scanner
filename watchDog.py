import os
import json
import hashlib
import shutil
from pathlib import Path
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import getpass
import time
import math

# ============================================================
# CONFIG
# ============================================================
QUARANTINE_FOLDER = "quarantine"
BAD_HASHES_FILE = "bad_hashes.json"

SCAN_EXTENSIONS = [
    ".exe", ".dll", ".bat", ".cmd", ".ps1", ".vbs", ".js",
    ".txt", ".json"
]

# Ignore temporary download files
IGNORE_EXTENSIONS = [
    ".crdownload", ".download", ".tmp", ".partial"
]

EICAR_SIGNATURE = (
    "X5O!P%@AP[4\\PZX54(P^)7CC)7}$"
    "EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
)

EICAR_HASHES = {
    "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
    "131f95c51cc819465fa1797f6ccacf9d494aaaff46fa3eac73ae63ffbdfd8267",
}

# ============================================================
# LOAD BAD HASHES
# ============================================================
if os.path.exists(BAD_HASHES_FILE):
    with open(BAD_HASHES_FILE, "r") as f:
        BAD_HASHES = set(json.load(f).get("sha256", []))
else:
    BAD_HASHES = set()


# ============================================================
# UTILITY FUNCTIONS
# ============================================================
def sha256_file(path: Path) -> str:
    sha = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            for block in iter(lambda: f.read(4096), b""):
                sha.update(block)
    except:
        return ""
    return sha.hexdigest()


def file_entropy(path: Path, max_bytes: int = 65536) -> float:
    try:
        with open(path, "rb") as f:
            data = f.read(max_bytes)
    except:
        return 0.0

    if not data:
        return 0.0

    freq = {}
    for b in data:
        freq[b] = freq.get(b, 0) + 1

    entropy = 0.0
    length = len(data)
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)

    return entropy


def has_pe_header(path: Path) -> bool:
    try:
        with open(path, "rb") as f:
            header = f.read(2)
        return header == b"MZ"
    except:
        return False


def has_suspicious_double_extension(path: Path) -> bool:
    name = path.name.lower()
    parts = name.split(".")
    if len(parts) < 3:
        return False

    last = parts[-1]
    prev = parts[-2]

    risky_last = {"exe", "bat", "cmd", "scr", "ps1"}
    common_prev = {
        "txt", "pdf", "doc", "docx", "xls", "xlsx",
        "png", "jpg", "jpeg", "gif", "zip", "rar"
    }

    return last in risky_last and prev in common_prev


def contains_suspicious_patterns(path: Path) -> bool:
    if path.suffix.lower() not in [".txt", ".json", ".bat", ".cmd", ".ps1", ".vbs", ".js"]:
        return False

    try:
        content = path.read_text(errors="ignore")
    except:
        return False

    lower = content.lower()

    patterns = [
        "powershell",
        "cmd /c",
        "invoke-webrequest",
        "wget ",
        "curl ",
        "http://",
        "https://",
        "<script>",
        "eval(",
        "base64",
    ]

    return any(p in lower for p in patterns)


def contains_eicar_signature(path: Path) -> bool:
    try:
        content = path.read_text(errors="ignore")
    except:
        return False

    return EICAR_SIGNATURE.lower() in content.lower()


def is_still_being_written(path: Path) -> bool:
    """Prevents scanning while file is downloading/writing."""
    try:
        size1 = path.stat().st_size
        time.sleep(0.8)
        size2 = path.stat().st_size
        return size1 != size2
    except:
        return False


def heuristic_score(path: Path) -> int:
    score = 0
    ext = path.suffix.lower()

    try:
        size = path.stat().st_size
    except:
        size = 0

    if ext == ".exe":
        # Much safer threshold than before
        if 0 < size < 5000:   # was 20 KB; now 5 KB
            score += 2

        if size > 200_000_000:
            score += 1

        ent = file_entropy(path)
        if ent > 7.2:
            score += 1

    if ext in [".txt", ".json"]:
        try:
            path.read_text()
        except:
            score += 2

    if has_pe_header(path) and ext not in [".exe", ".dll", ".sys", ".ocx", ".scr"]:
        score += 2

    if has_suspicious_double_extension(path):
        score += 2

    return score


def move_to_quarantine(path: Path):
    os.makedirs(QUARANTINE_FOLDER, exist_ok=True)
    target = Path(QUARANTINE_FOLDER) / path.name

    counter = 1
    while target.exists():
        target = Path(QUARANTINE_FOLDER) / f"{path.stem}_{counter}{path.suffix}"
        counter += 1

    try:
        shutil.move(str(path), str(target))
    except:
        pass


# ============================================================
# ANALYSIS LOGIC
# ============================================================
def analyze_file(path: Path):
    ext = path.suffix.lower()

    # Skip temporary download files
    if ext in IGNORE_EXTENSIONS:
        return

    if not path.exists() or not path.is_file():
        return

    # Skip active downloads (F I X)
    if is_still_being_written(path):
        return

    # EICAR & known hashes
    file_hash = sha256_file(path)
    if file_hash in EICAR_HASHES or file_hash in BAD_HASHES:
        move_to_quarantine(path)
        return

    if contains_eicar_signature(path):
        move_to_quarantine(path)
        return

    # Script / text pattern detection
    if contains_suspicious_patterns(path):
        move_to_quarantine(path)
        return

    # Heuristics
    score = heuristic_score(path)
    if score >= 2:
        move_to_quarantine(path)
        return


# ============================================================
# WATCHDOG HANDLER
# ============================================================
class WatchDogHandler(FileSystemEventHandler):
    def on_created(self, event):
        if not event.is_directory:
            analyze_file(Path(event.src_path))

    def on_modified(self, event):
        if not event.is_directory:
            analyze_file(Path(event.src_path))


# ============================================================
# START BACKGROUND WATCHER
# ============================================================
def start_background_watcher():
    username = getpass.getuser()
    base = Path(f"C:/Users/{username}")

    watch_dirs = [
        base / "Downloads",
        base / "Desktop",
        base / "Documents",
        base / "AppData/Local/Temp",
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


if __name__ == "__main__":
    start_background_watcher()