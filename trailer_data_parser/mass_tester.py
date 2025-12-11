import os
from pathlib import Path

from loguru import logger

from trailer_data_parser.parser import SamsungSEFEditor

# ================= CONFIGURATION =================
TEST_ROOT_DIR = "/home/kfir/Desktop/scrambler/trailer_data_research_ds_mod"  # Folder with subfolders
TARGET_TAG_ID = 0xa01  # Image_UTC_Data (Standard test target)
TEST_VALUE_STR = "1111111111111"  # 13 chars (Same len as original usually)


# =================================================

def compare_binary(original_entry, new_entry):
    """Returns True if Value, Padding, and Head-Padding are identical."""
    if original_entry['value'] != new_entry['value']: return False
    if original_entry['padding'] != new_entry['padding']: return False
    if original_entry.get('head_padding', b'') != new_entry.get('head_padding', b''): return False
    return True


def run_forensic_test(filepath):
    temp_output = str(filepath) + ".temp_test.jpg"

    try:
        # --- STEP 1: LOAD ORIGINAL ---
        orig_editor = SamsungSEFEditor(filepath)
        if not orig_editor.entries:
            return False, "SKIP: No SEF data found"

        # Snapshot original state {id: entry_dict}
        original_state = {e['entry_id']: e for e in orig_editor.entries}

        if TARGET_TAG_ID not in original_state:
            return False, f"SKIP: Target tag {hex(TARGET_TAG_ID)} not found in file"

        # --- STEP 2: MODIFY ---
        # Modify ONLY the UTC Data
        orig_editor.add_or_update_entry(TARGET_TAG_ID, TEST_VALUE_STR)

        # --- STEP 3: SAVE ---
        orig_editor.save(temp_output)

        # --- STEP 4: RELOAD & VERIFY ---
        new_editor = SamsungSEFEditor(temp_output)
        new_state = {e['entry_id']: e for e in new_editor.entries}

        # CHECK A: MODIFICATION (The target tag)
        target = new_state.get(TARGET_TAG_ID)
        if not target:
            return False, "FAIL: Target tag disappeared after save"

        # Check Value
        val_str = target['value'].decode('utf-8', errors='ignore')
        if TEST_VALUE_STR not in val_str:
            return False, f"FAIL: Value mismatch. Got {val_str}"

        # Check Alignment (New padding must be 0x00 and valid length)
        # Note: We rely on the class logic, but visual check:
        if any(b != 0 for b in target['padding']):
            return False, "FAIL: Modified tag has non-zero padding (Dirty)"

        # CHECK B: INTEGRITY (All other tags)
        for tid, orig_entry in original_state.items():
            if tid == TARGET_TAG_ID: continue  # Skip the one we modified

            if tid not in new_state:
                return False, f"FAIL: Integrity Lost. Tag {hex(tid)} vanished."

            new_entry = new_state[tid]

            # BIT-PERFECT CHECK
            # We compare the binary chunks directly.
            # If the head_padding (garbage) or tail_padding changed even by 1 byte, this fails.
            if not compare_binary(orig_entry, new_entry):
                return False, f"FAIL: Integrity Violation on {hex(tid)}. Data shifted."

    except Exception as e:
        return False, f"CRASH: {str(e)}"

    finally:
        if os.path.exists(temp_output):
            os.remove(temp_output)

    return True, "PASSED (Forensic Match)"


def main():
    root = Path(TEST_ROOT_DIR)
    stats = {"passed": 0, "failed": 0, "skipped": 0}
    failures = []

    print(f"🕵️  Running Forensic Integrity Suite on: {root}\n")

    for file_path in root.rglob('*'):
        if file_path.is_file() and file_path.suffix.lower() in ['.jpg', '.jpeg']:

            print(f"Testing: {file_path.name}...", end="\r")

            success, msg = run_forensic_test(str(file_path))

            if success:
                stats["passed"] += 1
            else:
                if "SKIP" in msg:
                    stats["skipped"] += 1
                else:
                    stats["failed"] += 1
                    failures.append(f"{file_path.name}: {msg}")
                    logger.error(f"{file_path.name} | {msg}")

    print("\n" + "=" * 50)
    print(f"  FORENSIC REPORT")
    print("=" * 50)
    print(f"✅ PASSED (Bit-Perfect): {stats['passed']}")
    print(f"❌ FAILED (Corruption):   {stats['failed']}")
    print(f"⏭ SKIPPED:               {stats['skipped']}")
    print("=" * 50)

    if failures:
        print("\nFAILURE DETAILS:")
        for f in failures:
            print(f" - {f}")


if __name__ == "__main__":
    main()
