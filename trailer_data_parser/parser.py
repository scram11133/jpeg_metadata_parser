import struct
import os
import re
from loguru import logger


class SamsungSEFEditor:
    SEFT_MAGIC = b'SEFT'
    SEFH_MAGIC = b'SEFH'

    # Encapsulation Styles
    ENCAP_RAW = 0  # Value only
    ENCAP_DIRECT = 1  # Name + Value
    ENCAP_NULL = 2  # Name + \x00 + Value

    # Full Mapping
    SEF_TAG_MAP = {
        0x001: "Generic_SubImage", 0xb41: "Generic_DepthMap", 0xba1: "PhotoEditor_Data",
        0x100: "SoundShot_Audio", 0x800: "SoundShot_Meta_Info", 0x8c0: "Auto_Enhance_Info",
        0x8e0: "Panorama_Shot_Info", 0x910: "Front_Cam_Selfie_Info", 0x9e0: "Burst_Shot_Info",
        0x9e1: "BurstShot_Best_Photo_Info", 0x9f0: "Pro_Mode_Info", 0xa01: "Image_UTC_Data",
        0xa30: "MotionPhoto_Data", 0xa41: "BackupRestore_Data", 0xaa1: "MCC_Data",
        0xab0: "DualShot_Meta_Info", 0xab1: "DualShot_DepthMap_1", 0xab3: "DualShot_Extra_Info",
        0xab4: "DualShot_Core_Info", 0xb30: "Camera_Sticker_Info", 0xb40: "SingleShot_Meta_Info",
        0xb51: "Intelligent_PhotoEditor_Data", 0xb60: "UltraWide_PhotoEditor_Data",
        0xb8a: "Single_Take_Info", 0xb90: "Document_Scan_Info", 0xba2: "Copy_Available_Edit_Info",
        0xbc0: "Single_Relighting_Bokeh_Info", 0xbd0: "Dual_Relighting_Bokeh_Info",
        0xbe0: "Livefocus_JDM_Info", 0xbf0: "Remaster_Info", 0xc21: "Portrait_Effect_Info",
        0xc51: "Samsung_Capture_Info", 0xc61: "Camera_Capture_Mode_Info", 0xc71: "Pro_White_Balance_Info",
        0xc81: "Watermark_Info", 0xcc1: "Color_Display_P3", 0xcd2: "Photo_HDR_Info",
        0xce1: "Gallery_DC_Data", 0xd01: "Camera_Scene_Info", 0xd11: "Video_Snapshot_Info",
        0xd31: "Food_Blur_Effect_Info", 0xd91: "PEg_Info", 0xda1: "Captured_App_Info"
    }

    DEFAULT_EMBEDDED_IDS = [0x001, 0xb41, 0xc81, 0xd11, 0xd31, 0xa01, 0xba1, 0x910, 0xc61]

    def __init__(self, filepath):
        self.filepath = filepath
        self.jpeg_data = b''
        self.entries = []
        self.version = 107
        self._load()

    def _load(self):
        if not os.path.exists(self.filepath):
            logger.error(f"File {self.filepath} not found")
            return

        with open(self.filepath, 'rb') as f:
            data = f.read()

        if data[-4:] != self.SEFT_MAGIC:
            logger.warning("No SEF data found. Starting with clean JPEG.")
            self.jpeg_data = data
            return

        # 1. Parse Structure
        try:
            dir_len = struct.unpack('<I', data[-8:-4])[0]
            dir_start = len(data) - 8 - dir_len
            if dir_start < 0: raise ValueError

            self.version = struct.unpack('<I', data[dir_start + 4:dir_start + 8])[0]
            count = struct.unpack('<I', data[dir_start + 8:dir_start + 12])[0]
            stride = int((dir_len - 12) / count) if count > 0 else 12
        except:
            logger.error("Corrupt SEF structure.")
            self.jpeg_data = data
            return

        # 2. Extract Layout
        table_start = dir_start + 12
        raw_entries = []

        for i in range(count):
            base = table_start + (i * stride)
            chunk = data[base:base + stride]

            offset = struct.unpack('<I', chunk[-8:-4])[0]
            length = struct.unpack('<I', chunk[-4:])[0]
            type_bytes = chunk[:-8]

            if len(type_bytes) == 4:
                tid = struct.unpack('<I', type_bytes)[0]
                if (tid & 0xFFFF == 0) and (tid > 0): tid = tid >> 16
            elif len(type_bytes) == 2:
                tid = struct.unpack('<H', type_bytes)[0]
            else:
                tid = 0

            data_start_abs = dir_start - offset
            data_end_abs = data_start_abs + length

            if data_start_abs < 0: continue

            raw_entries.append({
                'entry_id': tid,
                'start': data_start_abs,
                'end': data_end_abs,
                'length': length
            })

        # 3. Sort by Position
        raw_entries.sort(key=lambda x: x['start'])

        # 4. Harvest Data & Padding
        for i, entry in enumerate(raw_entries):
            # Payload
            raw_payload = data[entry['start']: entry['end']]

            # Padding (Gap to next item)
            if i < len(raw_entries) - 1:
                next_start = raw_entries[i + 1]['start']
            else:
                next_start = dir_start

            if next_start < entry['end']:
                padding_bytes = b''
            else:
                padding_bytes = data[entry['end']: next_start]

            # Analysis (Now returns head_padding too)
            name, clean_val, encap_style, head_pad = self._analyze_payload(entry['entry_id'], raw_payload)

            self.entries.append({
                'entry_id': entry['entry_id'],
                'name': name,
                'value': clean_val,
                'padding': padding_bytes,  # Tail Padding (Gap)
                'head_padding': head_pad,  # Head Padding (Garbage before name)
                'encap_type': encap_style,
                'is_modified': False
            })

        # JPEG Isolation
        if raw_entries:
            split_point = raw_entries[0]['start']
            self.jpeg_data = data[:split_point]
        else:
            self.jpeg_data = data[:dir_start]

        logger.success(f"Loaded {len(self.entries)} entries (Preservation Mode).")

    def _analyze_payload(self, tid, payload):
        """
        Returns: Name, Value, EncapStyle, HeadPadding
        """
        expected_name = self.SEF_TAG_MAP.get(tid, f"Tag_{hex(tid)}")
        head_padding = b''

        # 1. Search for Name (Allow it to be offset by garbage)
        try:
            head_str = payload[:100].decode('latin-1')
            if expected_name in head_str:
                # Remove ^ anchor to find name even if there is junk before it
                match = re.search(re.escape(expected_name), head_str)
                if match:
                    val_start = match.end()
                    name_start = match.start()

                    # Capture Head Padding (Garbage before name)
                    if name_start > 0:
                        head_padding = payload[:name_start]

                    # Determine Style
                    if val_start < len(payload) and payload[val_start] == 0:
                        return expected_name, payload[val_start + 1:], self.ENCAP_NULL, head_padding
                    else:
                        return expected_name, payload[val_start:], self.ENCAP_DIRECT, head_padding
        except:
            pass

        # 2. Check Generic Null Split
        try:
            if b'\x00' in payload[:64]:
                parts = payload.split(b'\x00', 1)
                name_cand = parts[0].decode('utf-8')
                if re.match(r'^[A-Za-z0-9_]+$', name_cand):
                    return name_cand, parts[1], self.ENCAP_NULL, b''
        except:
            pass

        # 3. Raw Fallback
        return expected_name, payload, self.ENCAP_RAW, b''

    # --- CRUD ---

    def add_or_update_entry(self, key_id, value, name=None):
        final_id = self._resolve_id(key_id)
        if final_id == 0: return

        # Convert
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

        if not name:
            name = self.SEF_TAG_MAP.get(final_id, f"Tag_{hex(final_id)}")

        # Update
        for entry in self.entries:
            if entry['entry_id'] == final_id:
                entry['value'] = binary_payload
                entry['name'] = name
                entry['is_modified'] = True

                # Upgrade mis-detected Raw types
                if final_id in self.DEFAULT_EMBEDDED_IDS:
                    if entry['encap_type'] == self.ENCAP_RAW:
                        if final_id in [0xa01, 0xc61]:
                            entry['encap_type'] = self.ENCAP_DIRECT
                        else:
                            entry['encap_type'] = self.ENCAP_NULL

                logger.info(f"Updated {hex(final_id)}")
                return

        # Add New
        def_encap = self.ENCAP_RAW
        if final_id in self.DEFAULT_EMBEDDED_IDS:
            if final_id in [0xa01, 0xc61]:
                def_encap = self.ENCAP_DIRECT
            else:
                def_encap = self.ENCAP_NULL

        self.entries.append({
            'entry_id': final_id, 'name': name, 'value': binary_payload,
            'padding': b'', 'head_padding': b'', 'encap_type': def_encap, 'is_modified': True
        })
        logger.info(f"Added {hex(final_id)}")

    def _resolve_id(self, key):
        if isinstance(key, int): return key
        if isinstance(key, str):
            if key.lower().startswith("0x"):
                try:
                    return int(key, 16)
                except:
                    pass
            else:
                for tid, tname in self.SEF_TAG_MAP.items():
                    if tname == key: return tid
        return 0

    # --- SAVE ---

    def _validate_integrity(self):
        seen = set()
        for e in self.entries:
            if e['entry_id'] in seen:
                logger.critical(f"INTEGRITY FAIL: Duplicate ID {hex(e['entry_id'])}")
                return False
            seen.add(e['entry_id'])
        return True

    def save(self, output_path):
        if not self._validate_integrity(): return
        logger.info(f"Rebuilding PRESERVED SEF trailer for {output_path}...")

        packed_blocks = []

        for e in self.entries:
            val = e['value']
            name = e['name']
            encap = e['encap_type']
            head_pad = e.get('head_padding', b'')  # Restore head garbage

            # Reconstruct Payload
            # Start with Head Padding (The garbage before the name)
            final_payload = head_pad

            # Append Encapsulated Data
            if encap == self.ENCAP_DIRECT:
                # Only add name if val doesn't already have it
                if not val.startswith(name.encode('utf-8')):
                    final_payload += name.encode('utf-8') + val
                else:
                    final_payload += val

            elif encap == self.ENCAP_NULL:
                name_bytes = name.encode('utf-8') + b'\x00'
                if not val.startswith(name_bytes):
                    final_payload += name_bytes + val
                else:
                    final_payload += val

            elif encap == self.ENCAP_RAW:
                final_payload += val

            # Handle Tail Padding
            final_padding = b''
            if not e['is_modified']:
                final_padding = e['padding']
            else:
                # Recalculate strict alignment for dirty items
                real_len = len(final_payload)
                remainder = real_len % 4
                if remainder != 0:
                    final_padding = b'\x00' * (4 - remainder)

            packed_blocks.append({
                'entry_id': e['entry_id'],
                'data': final_payload + final_padding,
                'table_len': len(final_payload)
            })

        # Physical Write
        full_data_block = b''
        for block in packed_blocks:
            full_data_block += block['data']

        table_bytes = b''
        current_cursor = 0
        total_phys_len = len(full_data_block)

        for block in packed_blocks:
            d_len = len(block['data'])
            d_offset = total_phys_len - current_cursor
            id_val = block['entry_id'] << 16
            entry_bin = struct.pack('<III', id_val, d_offset, block['table_len'])
            table_bytes += entry_bin
            current_cursor += d_len

        # Header
        current_count = len(self.entries)
        header = self.SEFH_MAGIC + \
                 struct.pack('<I', self.version) + \
                 struct.pack('<I', current_count)
        directory = header + table_bytes
        footer = struct.pack('<I', len(directory)) + self.SEFT_MAGIC

        try:
            with open(output_path, 'wb') as f:
                f.write(self.jpeg_data)
                f.write(full_data_block)
                f.write(directory)
                f.write(footer)
            logger.success(f"Saved (Preserved).")
        except Exception as e:
            logger.error(f"Write failed: {e}")