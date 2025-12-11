import os
import shutil
from pathlib import Path

# Configuration
SOURCE_DIR = "/home/kfir/Desktop/scrambler/trailer_data_research_ds"
DEST_DIR = "/home/kfir/Desktop/scrambler/trailer_data_research_ds_mod"


def has_sef_trailer(filepath):
    """
    Checks if a file has the Samsung SEF Trailer (SEFT).
    Reads only the last 4 bytes for speed.
    """
    try:
        with open(filepath, 'rb') as f:
            # seek to 4 bytes before the end
            f.seek(-4, os.SEEK_END)
            signature = f.read(4)
            return signature == b'SEFT'
    except Exception:
        return False


def copy_sef_images(src_root, dest_root):
    src_path = Path(src_root)
    dest_path = Path(dest_root)

    count = 0

    print(f"Scanning: {src_path}")
    print(f"Target:   {dest_path}\n")

    # Walk through the directory tree
    for file_path in src_path.rglob('*'):
        if file_path.is_file():
            # Check extension (case insensitive)
            if file_path.suffix.lower() in ['.jpg', '.jpeg']:

                if has_sef_trailer(file_path):
                    rel_path = file_path.relative_to(src_path)
                    target_file = dest_path / rel_path
                    target_file.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(file_path, target_file)
                    print(f"[COPIED] {rel_path}")
                    count += 1

    print(f"\nDone. Copied {count} files with SEF data.")


if __name__ == "__main__":
    copy_sef_images(SOURCE_DIR, DEST_DIR)