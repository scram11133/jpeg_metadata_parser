# Samsung SEF (Samsung Extended Format) Analysis & Editor

## 1. Project Overview
This project involves the reverse engineering, parsing, and modification of Samsung's proprietary **SEF** (Samsung Extended Format) metadata trailer. This binary structure is appended to the end of JPEG files captured by Samsung devices (Galaxy S, Note, and A series) and contains features such as **Motion Photos**, **Depth Maps (Portrait Mode)**, **Re-Edit Data**, and **Camera Modes**.

The resulting tool is a Python-based editor capable of **Non-Destructive Parsing**, **Forensic Preservation**, and **Safe Modification** of this data without corrupting the file structure or losing metadata.

---

## 2. File Structure (The "Backwards" Layout)

Unlike standard JPEG markers (EXIF/XMP) which exist in the header, SEF data is appended **after the EOI (End of Image) marker** (`FF D9`).

The file must be parsed **from the end of the file backwards**.

| Segment | Size | Description |
| :--- | :--- | :--- |
| **JPEG Data** | Variable | Standard JPEG image (starts `FF D8`, ends `FF D9`). |
| **Data Blocks** | Variable | The actual payloads (Videos, Depth Images, JSON, Text). Packed contiguously. |
| **SEFH Header** | 12 Bytes | Start of the "Directory". Contains Magic, Version, Count. |
| **Index Table** | Variable | List of pointers defining where the Data Blocks are located. |
| **Directory Len** | 4 Bytes | Integer size of the Directory (Header + Table). |
| **SEFT Footer** | 4 Bytes | Magic Signature `SEFT`. The anchor point for parsing. |

### The SEF Directory Structure
The "Directory" is the map of the file. It sits *after* the data blocks.

1.  **Header (12 Bytes):**
    * `Magic`: `SEFH` (ASCII)
    * `Version`: 4 Bytes Little Endian (Usually `107` for newer devices, `101` for older).
    * `Count`: 4 Bytes Little Endian (Number of entries in the table).

2.  **Index Table (Variable):**
    * Each entry is typically **12 Bytes** (Stride).
    * **ID:** 4 Bytes (Little Endian). The upper 2 bytes are the ID (e.g., `0xA01`), lower 2 bytes are flags/zero.
    * **Offset:** 4 Bytes. The distance **backwards** from the start of the `SEFH` header to the *start* of the Data Block.
    * **Length:** 4 Bytes. The size of the Data Block (excluding padding).

---

## 3. Key Findings & Logic

### A. 4-Byte Forensic Alignment
Samsung's file writer aligns all data blocks to **4-byte boundaries** for CPU efficiency (ARM architecture).
* **Physical Size:** Must be divisible by 4.
* **Logical Size:** The actual data length (stored in the Index Table).
* **Padding:** Null bytes (`0x00`) are added to the end of a block to fill the gap.
    * *Formula:* `Padding = (4 - (Length % 4)) % 4`
* **Preservation:** Original files often contain "garbage" memory data in the padding. Our editor cleans this to `0x00`, which changes the binary hash but keeps the data valid.

### B. Encapsulation Styles (The "Key Name" logic)
Metadata entries are not just raw values. They are often "Encapsulated" with their Key Name inside the binary payload. We identified three distinct styles:

| Style | Description | Used By (Examples) |
| :--- | :--- | :--- |
| **Raw** | Just the binary data. No name string. | `0xa30` (Motion Photo Video), `0xaa1` (MCC) |
| **Direct** | `KeyName` + `Value` (Concatenated). No separator. | `0xa01` (Timestamp), **`0xc61` (Camera Mode)** |
| **Null** | `KeyName` + `0x00` + `Value`. | `0x001` (Sub-Image), `0xb41` (Depth Map) |

**Critical Bug Fix:** Initially, we assumed only timestamps used "Direct" style. We discovered that **Camera Capture Mode (`0xc61`)** also uses Direct style. Adding a null byte there (`.1` instead of `1`) corrupted the data.

### C. Duplicate IDs vs. Singletons
* **Generic Containers:** IDs like `0x001` and `0xb41` are containers. A file can have multiple entries with ID `0x001` as long as they have unique **Internal Names** (e.g., "DualShot_1", "DualShot_2").
* **Singletons:** IDs like `0xa01` (Timestamp) or `0xa30` (Video) must be unique. Adding a duplicate confuses the parser.

---

## 4. Tag Reference Table (SEF_TAG_MAP)

These are the proprietary Tag IDs identified during the investigation:

| Hex ID | Name / Purpose | Content Type |
| :--- | :--- | :--- |
| `0xa01` | **Image_UTC_Data** | String (Timestamp, Direct Encap) |
| `0xa30` | **MotionPhoto_Data** | Binary (MP4 Video) |
| `0xaa1` | **MCC_Data** | Integer/Binary (Mobile Country Code) |
| `0xc61` | **Camera_Capture_Mode_Info** | String/Int (Direct Encap) |
| `0x001` | **Generic_SubImage** | JPEG (Thumbnail, DualShot) |
| `0xb41` | **Generic_DepthMap** | PNG/Gray (Portrait Depth) |
| `0xba1` | **PhotoEditor_Data** | JSON (Re-edit history) |
| `0x910` | **Front_Cam_Selfie_Info** | String/Binary |
| `0xd11` | **Video_Snapshot_Info** | String/Binary |
| `0xab1` | **DualShot_DepthMap_1** | Depth Map |
| `0x800` | **SoundShot_Meta_Info** | Audio Metadata |

---

## 5. The Editor Architecture (`SamsungSEFEditorGold`)

The final Python class implements a **Rebuild Strategy** rather than an in-place patch.

### Workflow:
1.  **Load:**
    * Locate `SEFT`.
    * Read Directory.
    * **Harvest Padding:** Calculate gaps between blocks to analyze original structure.
    * **Detect Encapsulation:** Regex scan to determine if an entry is `Raw`, `Direct`, or `Null`.
2.  **Modify (`add_or_update_entry`):**
    * Accepts input as Hex ID (`0xa01`), String (`"0xa01"`), or Name (`"Image_UTC_Data"`).
    * **Enforcement:** If modifying a known Embedded ID (like `0xa01`), it forces the correct Encapsulation Style, correcting any previous parsing errors.
    * Prevents duplicates for Singleton tags.
3.  **Save:**
    * **Reconstruct:** Re-assembles the Key Name and Value based on the detected style.
    * **Align:** Calculates strict 4-byte padding (`0x00`) for every block.
    * **Stack:** Writes data linearly (defragmented).
    * **Pointer Update:** Calculates new Offsets and Lengths.
    * **Header Update:** Writes new Count and Version.

### Usage Example
```python
from samsung_sef_gold import SamsungSEFEditorGold

# Load File
editor = SamsungSEFEditorGold("original.jpg")

# Update Timestamp (Handles Direct Encapsulation automatically)
editor.add_or_update_entry("Image_UTC_Data", "1764228059579")

# Add Motion Photo (Handles Raw Binary automatically)
with open("video.mp4", "rb") as f:
    editor.add_or_update_entry("MotionPhoto_Data", f.read())

# Save (Applies Forensic Alignment)
editor.save("modified.jpg")