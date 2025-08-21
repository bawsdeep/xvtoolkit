import os
import hashlib

HEADER_SIZE = 0x80
ID_OFFSET = 0x08  # "#SAV"
MAGIC = bytes([0x23, 0x53, 0x41, 0x56])
MARKER = bytes([0x47, 0xFE, 0xDF, 0x4C, 0x55, 0x54, 0xD6, 0x20])


def hex_words_to_bytes(words):
    """Convert iterable of 8-hex-digit strings (DWORDs) to bytes in order."""
    out = bytearray()
    for w in words:
        if len(w) != 8:
            raise ValueError("Each hex word must be 8 hex digits.")
        for i in range(0, 8, 2):
            out.append(int(w[i:i+2], 16))
    return bytes(out)


# Fallback 0x80-byte header (32 DWORDs)
FALLBACK_HEADER = hex_words_to_bytes([
    "23534156","00EDF699","C2DC2F81","E423D8D5","745D0E8C","87FCB668","B50F04B8","34A076F0",
    "16F518A5","1BCCDF6C","6DE43982","A112BAA2","E036BAAE","60007F50","03A4A7E6","741AFD98",
    "F49F5A22","91BE17BC","BC28D137","B3AA7B1C","5D5B03CE","807F7D29","C2DDBE12","0739E8FA",
    "07758C0B","A0A9BFFC","68F63F38","96C28679","276F4383","98B5C34A","BADBBC66","60A11200",
])


def sha1_hex(data_bytes: bytes) -> str:
    return hashlib.sha1(data_bytes).hexdigest()


def has_dual_magic(d: bytes) -> bool:
    return len(d) >= 0x84 and d[0x00:0x04] == MAGIC and d[0x80:0x84] == MAGIC


def has_marker_at_08(d: bytes) -> bool:
    if len(MARKER) != 8:
        raise ValueError("MARKER must be exactly 8 bytes.")
    if len(d) < ID_OFFSET + len(MARKER):
        return False
    return d[ID_OFFSET:ID_OFFSET + len(MARKER)] == MARKER


def compute_base_name(file_name: str) -> str:
    name = file_name
    suffixes = [
        "EditorReady.sav.dec","SDATA000.DAT",".packed",".unpacked",
        "+EditorReady.sav.dec","+SDATA000.DAT"
    ]
    lower_name = name.lower()
    for s in suffixes:
        if lower_name.endswith(s.lower()):
            name = name[:len(name) - len(s)]
            break
    plus = name.find('+')
    if plus >= 0:
        name = name[:plus]
    dot = name.find('.')
    if dot >= 0:
        name = name[:dot]
    return name


def pack_data(data: bytes) -> bytes:
    if len(data) < HEADER_SIZE:
        raise ValueError("File too small to pack.")
    rotated = data[HEADER_SIZE:] + data[:HEADER_SIZE]
    with_marker = rotated[:ID_OFFSET] + MARKER + rotated[ID_OFFSET:] + (b"\x00" * 16)
    return with_marker


def unpack_data(data: bytes) -> bytes:
    if not has_marker_at_08(data):
        raise ValueError("Marker not found at 0x08.")
    if len(data) < HEADER_SIZE + 16 + 8:
        raise ValueError("File too small to unpack.")
    rm_marker = data[:ID_OFFSET] + data[ID_OFFSET + 8:]
    if len(rm_marker) < 16:
        raise ValueError("Corrupted structure (no room for padding).")
    base_data = rm_marker[:-16]
    if len(base_data) < HEADER_SIZE:
        raise ValueError("Corrupted structure (no header).")
    out_data = base_data[-HEADER_SIZE:] + base_data[:-HEADER_SIZE]
    return out_data


def fallback_unpack(data: bytes) -> bytes:
    if len(data) < ID_OFFSET + 8:
        raise ValueError("File too small for fallback edit.")
    rm8 = data[:ID_OFFSET] + data[ID_OFFSET + 8:]
    if len(rm8) < 16 + HEADER_SIZE:
        raise ValueError("File too small to remove padding and trailing header.")
    trimmed = rm8[:len(rm8) - 16 - HEADER_SIZE]
    out_data = bytearray(FALLBACK_HEADER + trimmed)
    out_data[-1] = 0x4C
    return bytes(out_data)


def process_file(input_path: str, mode: str = "auto") -> dict:
    """
    Process a file for PS4 -> PC conversion (or packing/unpacking)
    Returns a dictionary:
        {
            'output_path': str,
            'chosen': str,
            'input_sha1': str,
            'output_sha1': str
        }
    """
    if not os.path.isfile(input_path):
        raise FileNotFoundError(f"Input not found: {input_path}")

    with open(input_path, 'rb') as f:
        data = f.read()

    directory = os.path.dirname(os.path.abspath(input_path)) or "."
    base_name = compute_base_name(os.path.basename(input_path))

    if mode not in ("auto", "pack", "unpack"):
        raise ValueError(f"Invalid mode: {mode}")

    if mode == "pack" or (mode == "auto" and has_dual_magic(data)):
        if not has_dual_magic(data):
            raise ValueError("Refusing to pack: '#SAV' not present at both 0x00 and 0x80.")
        out_data = pack_data(data)
        out_path = os.path.join(directory, base_name + "EditorReady.sav.dec")
        chosen = "PACK"

    elif mode == "unpack" or (mode == "auto" and has_marker_at_08(data)):
        if not has_marker_at_08(data):
            raise ValueError("Refusing to unpack: marker not found at 0x08.")
        out_data = unpack_data(data)
        out_path = os.path.join(directory, base_name + "SDATA000.DAT")
        chosen = "UNPACK"

    else:
        out_data = fallback_unpack(data)
        out_path = os.path.join(directory, base_name + "SDATA000.DAT")
        chosen = "UNPACK-FALLBACK"

    with open(out_path, 'wb') as of:
        of.write(out_data)

    return {
        "output_path": out_path,
        "chosen": chosen,
        "input_sha1": sha1_hex(data),
        "output_sha1": sha1_hex(out_data)
    }


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage:\n  xv2_ps4topc.py <inputFile> (auto)\n  xv2_ps4topc.py pack <inputFile>\n  xv2_ps4topc.py unpack <inputFile>")
        sys.exit(2)

    mode = "auto"
    input_path = sys.argv[1]
    if len(sys.argv) > 2:
        mode = sys.argv[1].lower()
        input_path = sys.argv[2]

    try:
        result = process_file(input_path, mode)
        print(f"{result['chosen']} → {os.path.basename(result['output_path'])}")
        print(f"Input SHA1: {result['input_sha1']}")
        print(f"Output SHA1: {result['output_sha1']}")
        sys.exit(0)
    except Exception as ex:
        print("Error:", ex)
        sys.exit(1)
