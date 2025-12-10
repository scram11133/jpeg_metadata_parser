import os
import shutil

from loguru import logger

from parser import SamsungSEFEditorPreservation

# --- UPDATE 1: Import the new Preservation Class ---

# --- CONFIGURATION ---
INPUT_DIR = "/home/kfir/Desktop/scrambler/trailer_data_research_ds/samsung Galaxy S23 FE"
OUTPUT_DIR = "/home/kfir/Desktop/scrambler/trailer_data_research_ds/samsung Galaxy S23 FE/output"
TEST_TIMESTAMP = "1111111111111"


def setup_directories():
    if os.path.exists(OUTPUT_DIR):
        shutil.rmtree(OUTPUT_DIR)
    os.makedirs(OUTPUT_DIR)
    logger.info(f"Created clean output directory: {OUTPUT_DIR}")


def test_read_stability(filepath):
    """Test 1: Can we open the file without crashing?"""
    try:
        editor = SamsungSEFEditorPreservation(filepath)
        count = len(editor.entries)
        has_sef = count > 0
        status = "SEF FOUND" if has_sef else "CLEAN JPEG"
        logger.info(f"[READ] {os.path.basename(filepath):<25} | {status:<10} | {count} entries")
        return True, has_sef
    except Exception as e:
        logger.error(f"[READ FAIL] {os.path.basename(filepath)} | Error: {e}")
        return False, False


def test_idempotency(filepath):
    """Test 2: Integrity Check. Load -> Save -> Load."""
    filename = os.path.basename(filepath)
    save_path = os.path.join(OUTPUT_DIR, f"rebuild_{filename}")

    try:
        # 1. Load Original
        editor = SamsungSEFEditorPreservation(filepath)

        # Capture state (Now including padding and encap_type)
        # We strip 'is_dirty' because that resets on reload
        def get_state(ed):
            return str([{k: v for k, v in e.items() if k != 'is_dirty'} for e in ed.entries])

        original_repr = get_state(editor)

        # 2. Save Immediately (Should preserve garbage padding)
        editor.save(save_path)

        # 3. Load the Saved Copy
        editor_new = SamsungSEFEditorPreservation(save_path)
        new_repr = get_state(editor_new)

        # 4. Compare
        if original_repr == new_repr:
            logger.success(f"[INTEGRITY] {filename} passed reconstruction.")
            return True
        else:
            logger.error(f"[INTEGRITY FAIL] {filename} changed after save!")
            logger.debug(f"Original len: {len(original_repr)} | New len: {len(new_repr)}")
            return False

    except Exception as e:
        logger.exception(f"[INTEGRITY CRASH] {filename} | {e}")
        return False


def test_modification(filepath):
    """Test 3: CRUD. Add a timestamp and verify it works."""
    filename = os.path.basename(filepath)
    save_path = os.path.join(OUTPUT_DIR, f"mod_{filename}")

    try:
        editor = SamsungSEFEditorPreservation(filepath)

        # MODIFY: Update or Add UTC Timestamp
        editor.add_or_update_entry("Image_UTC_Data", TEST_TIMESTAMP)

        editor.save(save_path)

        # VERIFY
        checker = SamsungSEFEditorPreservation(save_path)

        found_val = None
        for e in checker.entries:
            if e['entry_id'] == 0xa01:
                found_val = e['value']
                break

        if found_val and found_val.decode('utf-8') == TEST_TIMESTAMP:
            logger.success(f"[MODIFY] {filename} successfully updated timestamp.")
            return True
        else:
            logger.error(f"[MODIFY FAIL] {filename} timestamp mismatch.")
            return False

    except Exception as e:
        logger.exception(f"[MODIFY CRASH] {filename} | {e}")
        return False


def test_preservation_logic(filepath):
    """Test 4: Verify that we are actually detecting encapsulation styles."""
    filename = os.path.basename(filepath)
    try:
        editor = SamsungSEFEditorPreservation(filepath)

        # Check specifically for Camera Mode (0xc61) or Timestamp (0xa01)
        # We want to see if it detected ENCAP_DIRECT (1) vs ENCAP_NULL (2)

        stats = {0: 0, 1: 0, 2: 0}  # Raw, Direct, Null

        for e in editor.entries:
            style = e.get('encap_type', 0)
            stats[style] += 1

        logger.info(f"[PRESERVE CHECK] {filename} | Styles Found -> Raw: {stats[0]}, Direct: {stats[1]}, Null: {stats[2]}")

        if stats[1] > 0 or stats[2] > 0:
            return True
        return False  # Passed if we found at least one encapsulated item

    except Exception as e:
        logger.error(f"[PRESERVE CHECK FAIL] {e}")
        return False


def run_suite():
    setup_directories()

    files = [f for f in os.listdir(INPUT_DIR) if f.lower().endswith(('.jpg', '.jpeg'))]

    if not files:
        logger.warning(f"No JPG images found in {INPUT_DIR}")
        return

    logger.info(f"Starting PRESERVATION test suite on {len(files)} images...")

    stats = {"passed": 0, "failed": 0}

    for f in files:
        f_path = os.path.join(INPUT_DIR, f)

        # 1. Stability
        ok_read, has_sef = test_read_stability(f_path)
        if not ok_read:
            stats["failed"] += 1
            continue

        # 2. Integrity
        if has_sef:
            if not test_idempotency(f_path):
                stats["failed"] += 1
                continue

            # 3. Preservation Check (New)
            test_preservation_logic(f_path)

        # 4. Modification
        if test_modification(f_path):
            stats["passed"] += 1
        else:
            stats["failed"] += 1

    logger.info("--- TEST SUMMARY ---")
    logger.success(f"Passed: {stats['passed']}")
    if stats['failed'] > 0:
        logger.error(f"Failed: {stats['failed']}")


if __name__ == "__main__":
    run_suite()