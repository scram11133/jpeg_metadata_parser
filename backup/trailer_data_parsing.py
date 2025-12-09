import struct
import os
import re
from loguru import logger


class SamsungSEFEditor:
    SEFT_MAGIC = b'SEFT'
    SEFH_MAGIC = b'SEFH'

    # --- CONFIGURATION ---

    # IDs that require the name to be re-embedded into the binary blob upon saving.
    EMBEDDED_KEY_IDS = [
        0x001, 0xb41, 0xc81, 0xd11, 0xd31, 0xa01, 0xba1, 0x910
    ]

    # Full Mapping from HackerFactor & Research
    SEF_TAG_MAP = {
        # Generic / Multi-Use Containers
        0x001: "Generic_SubImage",
        0xb41: "Generic_DepthMap",
        0xba1: "PhotoEditor_Data",

        # Audio
        0x100: "SoundShot_Audio",
        0x800: "SoundShot_Meta_Info",

        # Meta Info & Binary Blobs
        0x8c0: "Auto_Enhance_Info",
        0x8e0: "Panorama_Shot_Info",
        0x910: "Front_Cam_Selfie_Info",
        0x9e0: "Burst_Shot_Info",
        0x9e1: "BurstShot_Best_Photo_Info",
        0x9f0: "Pro_Mode_Info",
        0xa01: "Image_UTC_Data",
        0xa30: "MotionPhoto_Data",
        0xa41: "BackupRestore_Data",
        0xaa1: "MCC_Data",
        0xab0: "DualShot_Meta_Info",
        0xab1: "DualShot_DepthMap_1",
        0xab3: "DualShot_Extra_Info",
        0xab4: "DualShot_Core_Info",
        0xb30: "Camera_Sticker_Info",
        0xb40: "SingleShot_Meta_Info",
        0xb51: "Intelligent_PhotoEditor_Data",
        0xb60: "UltraWide_PhotoEditor_Data",
        0xb8a: "Single_Take_Info",
        0xb90: "Document_Scan_Info",
        0xba2: "Copy_Available_Edit_Info",
        0xbc0: "Single_Relighting_Bokeh_Info",
        0xbd0: "Dual_Relighting_Bokeh_Info",
        0xbe0: "Livefocus_JDM_Info",
        0xbf0: "Remaster_Info",
        0xc21: "Portrait_Effect_Info",
        0xc51: "Samsung_Capture_Info",
        0xc61: "Camera_Capture_Mode_Info",
        0xc71: "Pro_White_Balance_Info",
        0xc81: "Watermark_Info",
        0xcc1: "Color_Display_P3",
        0xcd2: "Photo_HDR_Info",
        0xce1: "Gallery_DC_Data",
        0xd01: "Camera_Scene_Info",
        0xd11: "Video_Snapshot_Info",
        0xd31: "Food_Blur_Effect_Info",
        0xd91: "PEg_Info",
        0xda1: "Captured_App_Info"
    }

    def __init__(self, filepath):
        self.filepath = filepath
        self.jpeg_data = b''
        self.entries = []
        self.version = 107
        self._load()

    def _load(self):
        """Initial parsing to populate the entries list."""
        if not os.path.exists(self.filepath):
            logger.error(f"File {self.filepath} not found")
            raise FileNotFoundError(f"File {self.filepath} not found")

        with open(self.filepath, 'rb') as f:
            data = f.read()

        # 1. Check for Trailer key
        if data[-4:] != self.SEFT_MAGIC:
            logger.info("No SEF data found (no SEFT footer found). Treating as clean JPEG.")
            self.jpeg_data = data
            return

        # 2. Extract Layout
        try:
            dir_len = struct.unpack('<I', data[-8:-4])[0]
            dir_start = len(data) - 8 - dir_len
            if dir_start < 0:
                raise ValueError
        except ValueError:
            logger.error("Corrupt SEF pointers. Treating as clean JPEG to preserve image.")
            self.jpeg_data = data
            return

        # 3. Read Header
        try:
            self.version = struct.unpack('<I', data[dir_start + 4:dir_start + 8])[0]
            count = struct.unpack('<I', data[dir_start + 8:dir_start + 12])[0]
            stride = int((dir_len - 12) / count) if count > 0 else 12
        except struct.error:
            logger.error("Failed to read Directory Header.")
            self.jpeg_data = data
            return

        # 4. Parse Entries
        table_start = dir_start + 12
        max_data_offset = 0

        for i in range(count):
            base = table_start + (i * stride)
            chunk = data[base:base + stride]

            offset = struct.unpack('<I', chunk[-8:-4])[0]
            length = struct.unpack('<I', chunk[-4:])[0]
            type_bytes = chunk[:-8]

            # Normalize ID
            if len(type_bytes) == 4:
                tid = struct.unpack('<I', type_bytes)[0]
                if (tid & 0xFFFF == 0) and (tid > 0): tid = tid >> 16
            elif len(type_bytes) == 2:
                tid = struct.unpack('<H', type_bytes)[0]
            else:
                tid = 0

            # Extract Payload
            data_loc = dir_start - offset

            if data_loc < 0 or data_loc + length > len(data):
                logger.warning(f"Entry {i} (ID {hex(tid)}) points out of bounds. Skipping.")
                continue

            raw_payload = data[data_loc: data_loc + length]

            if offset > max_data_offset: max_data_offset = offset

            name, clean_val = self._clean_payload(tid, raw_payload)

            self.entries.append({
                'id': tid,
                'name': name,
                'value': clean_val
            })

        # 5. Isolate JPEG
        split_point = dir_start - max_data_offset
        self.jpeg_data = data[:split_point]
        logger.success(
            f"Loaded {len(self.entries)} entries from {os.path.basename(self.filepath)}. JPEG Size: {len(self.jpeg_data)} bytes.")

    def _clean_payload(self, tid, payload):
        """Extracts embedded names and returns (Name, Value)."""
        expected_name = self.SEF_TAG_MAP.get(tid, f"Tag_{hex(tid)}")

        # Heuristic 1: Regex Match (Standardized)
        try:
            # Decode start of payload to string for searching
            head_str = payload[:100].decode('latin-1')

            if expected_name in head_str:
                match = re.search(re.escape(expected_name), head_str)
                if match:
                    val_start = match.end()

                    # BUG FIX: Check if the next byte is a null separator and skip it
                    if val_start < len(payload) and payload[val_start] == 0:
                        val_start += 1

                    return expected_name, payload[val_start:]
        except:
            pass

        # Heuristic 2: Null Byte Split (Generic fallback)
        try:
            if b'\x00' in payload[:64]:
                parts = payload.split(b'\x00', 1)
                name_cand = parts[0].decode('utf-8')
                if re.match(r'^[A-Za-z0-9_]+$', name_cand):
                    return name_cand, parts[1]
        except:
            pass

        return expected_name, payload

    # --- CRUD OPERATIONS ---

    def list_entries(self):
        logger.info(f"Listing {len(self.entries)} Trailer Entries:")
        for i, e in enumerate(self.entries):
            val_preview = str(e['value'])
            if len(e['value']) > 50:
                val_preview = f"<{len(e['value'])} bytes binary>"
            # Using standard logger to keep timestamps, or print raw table
            logger.info(f"[{i}] {hex(e['id']):<6} | {e['name']:<25} | {val_preview}")

    def get_entry(self, type_id):
        for e in self.entries:
            if e['id'] == type_id: return e
        return None

    def delete_entry(self, type_id):
        old_len = len(self.entries)
        self.entries = [e for e in self.entries if e['id'] != type_id]
        if len(self.entries) < old_len:
            logger.info(f"Deleted entry {hex(type_id)}")
        else:
            logger.warning(f"Attempted to delete ID {hex(type_id)} but it was not found.")

    def reorder_entries(self, new_indices):
        if len(new_indices) != len(self.entries):
            logger.error("Index count mismatch in reorder request.")
            return
        self.entries = [self.entries[i] for i in new_indices]
        logger.info("Entries reordered successfully.")

    def add_or_update_entry(self, key_id, value, name=None):
        """
        Adds a new entry or updates an existing one (Upsert logic).
        type_identifier: can be int (0xa01), hex string ("0xa01"), or name ("Image_UTC_Data")
        """

        # 1. Resolve ID
        final_id = 0
        if isinstance(key_id, int):
            final_id = key_id
        elif isinstance(key_id, str):
            if key_id.lower().startswith("0x"):
                try:
                    final_id = int(key_id, 16)
                except:
                    pass
            else:
                # Reverse lookup
                for tid, tname in self.SEF_TAG_MAP.items():
                    if tname == key_id:
                        final_id = tid
                        break

        if final_id == 0:
            logger.error(f"Unknown Tag Name or Invalid ID: {key_id}")
            return

        # 2. Convert Value to Bytes
        binary_payload = b''
        if isinstance(value, int):
            try:
                binary_payload = struct.pack('<I', value)
            except:
                binary_payload = str(value).encode('utf-8')
        elif isinstance(value, str):
            binary_payload = value.encode('utf-8')
        elif isinstance(value, (bytes, bytearray)):
            binary_payload = bytes(value)
        else:
            binary_payload = str(value).encode('utf-8')

        # 3. Resolve Name
        if not name:
            name = self.SEF_TAG_MAP.get(final_id, f"Tag_{hex(final_id)}")

        # 4. Upsert Logic (Strict - No Duplicates)
        for entry in self.entries:
            if entry['id'] == final_id:
                entry['value'] = binary_payload
                entry['name'] = name
                logger.info(f"Updated existing entry {hex(final_id)} ({name})")
                return

        # Not found? Add new.
        self.entries.append({'id': final_id, 'name': name, 'value': binary_payload})
        logger.info(f"Added new entry {hex(final_id)} ({name})")

    def save(self, output_path):
        logger.info(f"Building SEF trailer for {output_path}...")

        packed_blocks = []
        for e in self.entries:
            tid = e['id']
            val = e['value']
            name = e['name']

            final_payload = val

            if tid in self.EMBEDDED_KEY_IDS or tid in [0x001, 0xb41]:
                if tid == 0xa01:
                    if not val.startswith(name.encode('utf-8')):
                        final_payload = name.encode('utf-8') + val
                else:
                    name_bytes = name.encode('utf-8') + b'\x00'
                    if not val.startswith(name_bytes):
                        final_payload = name_bytes + val

            packed_blocks.append({'id': tid, 'data': final_payload})

        full_data_block = b''
        for block in packed_blocks:
            full_data_block += block['data']

        table_bytes = b''
        current_cursor = 0
        total_len = len(full_data_block)

        for block in packed_blocks:
            d_len = len(block['data'])
            d_offset = total_len - current_cursor

            id_val = block['id'] << 16

            entry_bin = struct.pack('<III', id_val, d_offset, d_len)
            table_bytes += entry_bin

            current_cursor += d_len

        current_count = len(self.entries)

        # Build the Header: Magic (4) + Version (4) + New Count (4)
        header = self.SEFH_MAGIC + \
                 struct.pack('<I', self.version) + \
                 struct.pack('<I', current_count)

        directory = header + table_bytes
        footer = struct.pack('<I', len(directory)) + self.SEFT_MAGIC

        with open(output_path, 'wb') as f:
            f.write(self.jpeg_data)
            f.write(full_data_block)
            f.write(directory)
            f.write(footer)

        logger.success(f"File successfully saved to {output_path}")
