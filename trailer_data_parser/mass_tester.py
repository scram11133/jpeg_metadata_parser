import os
import shutil
from pathlib import Path
from loguru import logger

from trailer_data_parser.parser import SamsungSEFEditor

# ================= CONFIGURATION =================
TEST_ROOT_DIR = "/home/kfir/Desktop/scrambler/trailer_data_research_ds_mod"
TARGET_TAG_ID = 0xa01  # Existing tag to Modify/Remove
TEST_VALUE_STR = "1111111111111"
DUMMY_TAG_ID = 0x999  # New tag to Add
DUMMY_TAG_NAME = "Forensic_Test_Tag"
DUMMY_VALUE = "Test_Data_123"


# =================================================

def compare_binary(original_entry, new_entry):
    """Returns True if Value, Padding, and Head-Padding are identical."""
    if original_entry['value'] != new_entry['value']: return False
    if original_entry['padding'] != new_entry['padding']: return False
    if original_entry.get('head_padding', b'') != new_entry.get('head_padding', b''): return False
    return True


def run_modification_test(filepath):
    """Standard Modification Test (Change Value)"""
    temp_output = str(filepath) + ".mod_test.jpg"
    try:
        orig_editor = SamsungSEFEditor(filepath)
        if not orig_editor.entries:
            print(f"SKIP: No SEF data in {filepath}")
            return False, "SKIP: No SEF data in {filepath}"

        # Snapshot
        original_state = {e['entry_id']: e for e in orig_editor.entries}
        if TARGET_TAG_ID not in original_state:
            print(f"SKIP: Target tag missing in {filepath}")
            return False, "SKIP: Target tag missing"

        # Modify
        orig_editor.add_or_update_entry(TARGET_TAG_ID, TEST_VALUE_STR)
        orig_editor.save(temp_output)

        # Verify
        new_editor = SamsungSEFEditor(temp_output)
        new_state = {e['entry_id']: e for e in new_editor.entries}

        # Check Target
        target = new_state.get(TARGET_TAG_ID)
        if not target: return False, "FAIL: Modified tag vanished"
        if TEST_VALUE_STR not in str(target['value']): return False, "FAIL: Value mismatch"

        # Check Integrity of others
        for tid, orig_entry in original_state.items():
            if tid == TARGET_TAG_ID: continue
            if tid not in new_state: return False, f"FAIL: Integrity Lost. {hex(tid)} vanished."
            if not compare_binary(orig_entry, new_state[tid]): return False, f"FAIL: Data shift on {hex(tid)}"

    except Exception as e:
        return False, f"CRASH: {str(e)}"
    finally:
        if os.path.exists(temp_output): os.remove(temp_output)
    return True, "PASSED"


def run_add_remove_test(filepath):
    """New Test: Add Entry -> Save -> Remove Entry -> Save"""
    temp_add = str(filepath) + ".add_test.jpg"
    temp_del = str(filepath) + ".del_test.jpg"

    try:
        # --- PHASE 1: ADD ENTRY ---
        orig_editor = SamsungSEFEditor(filepath)
        if not orig_editor.entries: return False, "SKIP: No SEF data"
        original_state = {e['entry_id']: e for e in orig_editor.entries}

        # Add new dummy entry
        orig_editor.add_or_update_entry(DUMMY_TAG_ID, DUMMY_VALUE, name=DUMMY_TAG_NAME)
        orig_editor.save(temp_add)

        # Verify Add
        add_editor = SamsungSEFEditor(temp_add)
        add_state = {e['entry_id']: e for e in add_editor.entries}

        if DUMMY_TAG_ID not in add_state:
            return False, "FAIL (Add): New tag not found after save"

        # Verify Integrity of OLD tags (Offsets should shift, but data must match)
        for tid, orig_entry in original_state.items():
            if not compare_binary(orig_entry, add_state[tid]):
                return False, f"FAIL (Add): Adding tag corrupted existing tag {hex(tid)}"

        # --- PHASE 2: REMOVE ENTRY ---
        # Remove the tag we just added
        add_editor.remove_entry(DUMMY_TAG_ID)
        add_editor.save(temp_del)

        # Verify Remove
        del_editor = SamsungSEFEditor(temp_del)
        del_state = {e['entry_id']: e for e in del_editor.entries}

        if DUMMY_TAG_ID in del_state:
            return False, "FAIL (Remove): Tag still exists after deletion"

        # Verify Integrity again (Should match original file exactly now?)
        # Note: If we removed the ONLY change we made, the file *content* for tags matches,
        # but the directory structure was rebuilt so offsets might differ, but payload must match.
        for tid, orig_entry in original_state.items():
            if tid not in del_state: return False, f"FAIL (Remove): Original tag {hex(tid)} lost."
            if not compare_binary(orig_entry, del_state[tid]):
                return False, f"FAIL (Remove): Deleting tag corrupted existing tag {hex(tid)}"

    except Exception as e:
        return False, f"CRASH: {str(e)}"
    finally:
        if os.path.exists(temp_add): os.remove(temp_add)
        if os.path.exists(temp_del): os.remove(temp_del)

    return True, "PASSED"


def main():
    root = Path(TEST_ROOT_DIR)
    stats = {"passed": 0, "failed": 0, "skipped": 0}
    failures = []

    print(f"🕵️  Running Forensic Suite (Mod + Add/Remove) on: {root}\n")

    for file_path in root.rglob('*'):
        if file_path.is_file() and file_path.suffix.lower() in ['.jpg', '.jpeg']:
            print(f"Testing: {file_path.name}...", end="\r")

            # Run Test 1: Modification
            s1, m1 = run_modification_test(str(file_path))

            # Run Test 2: Add/Remove
            s2, m2 = run_add_remove_test(str(file_path))

            if s1 and s2:
                stats["passed"] += 1
            elif "SKIP" in m1 or "SKIP" in m2:
                stats["skipped"] += 1
            else:
                stats["failed"] += 1
                reason = m1 if not s1 else m2
                failures.append(f"{file_path.name}: {reason}")
                logger.error(f"{file_path.name} | {reason}")

    print("\n" + "=" * 50)
    print(f"  FORENSIC REPORT")
    print("=" * 50)
    print(f"✅ PASSED (All Tests):   {stats['passed']}")
    print(f"❌ FAILED:               {stats['failed']}")
    print(f"⏭ SKIPPED:              {stats['skipped']}")
    print("=" * 50)

    if failures:
        print("\nFAILURE DETAILS:")
        for f in failures:
            print(f" - {f}")


if __name__ == "__main__":
    main()