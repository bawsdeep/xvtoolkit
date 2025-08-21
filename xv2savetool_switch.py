import os
import sys
import struct
import argparse
from typing import Dict, Any, List

from Crypto.Cipher import AES


def aes_ctr_crypt(key: bytes, initial_value: bytes, data: bytes) -> bytes:
    """CTR mode is symmetric; this mirrors Utils.AesCtrDecrypt in C#."""
    return AES.new(key, AES.MODE_CTR, initial_value=initial_value, nonce=b"").decrypt(data)


def get_random_bytes(num_bytes: int) -> bytes:
    return os.urandom(num_bytes)


class Xv2SavFile:
    """Port of Xv2SavFile.cs (Switch logic kept intact)."""

    # Encryption Keys (Section 1)
    Section1Key = b"PR]-<Q9*WxHsV8rcW!JuH7k_ug:T5ApX"
    Section1Counter = b"_Y7]mD1ziyH#Ar=0"

    def __init__(self, filename: str) -> None:
        # Dictionary of known PC file sizes
        self.file_sizes: Dict[int, Dict[str, Any]] = {
            0xB08C0: {
                "encrypted": True,
                "version": 8,
                "platform": "pc",
                "footer": bytes([0x41, 0xFE, 0x40, 0x91, 0xFC, 0xA0, 0x17, 0x98, 0x3C, 0x48, 0x78, 0xD8, 0xE5, 0x30, 0x8A, 0x61]),
            },
            0xB0818: {
                "encrypted": False,
                "version": 8,
                "platform": "pc",
                "footer": bytes([0x41, 0xFE, 0x40, 0x91, 0xFC, 0xA0, 0x17, 0x98, 0x3C, 0x48, 0x78, 0xD8, 0xE5, 0x30, 0x8A, 0x61]),
            },
            0xDF2A0: {
                "encrypted": True,
                "version": 17,
                "platform": "pc",
                "footer": bytes([0x6F, 0xF4, 0x5A, 0x72, 0x53, 0xFD, 0x9A, 0xA5, 0x6D, 0x7D, 0xAB, 0x47, 0x90, 0x46, 0x29, 0x96]),
            },
            0xDF1F8: {
                "encrypted": False,
                "version": 17,
                "platform": "pc",
                "footer": bytes([0x6F, 0xF4, 0x5A, 0x72, 0x53, 0xFD, 0x9A, 0xA5, 0x6D, 0x7D, 0xAB, 0x47, 0x90, 0x46, 0x29, 0x96]),
            },
            0x12A2A0: {
                "encrypted": True,
                "version": 20,
                "platform": "pc",
                "footer": bytes([0x6F, 0xF4, 0x5A, 0x72, 0x53, 0xFD, 0x9A, 0xA5, 0x6D, 0x7D, 0xAB, 0x47, 0x90, 0x46, 0x29, 0x96]),
            },
            0x12A1F8: {
                "encrypted": False,
                "version": 20,
                "platform": "pc",
                "footer": bytes([0x6F, 0xF4, 0x5A, 0x72, 0x53, 0xFD, 0x9A, 0xA5, 0x6D, 0x7D, 0xAB, 0x47, 0x90, 0x46, 0x29, 0x96]),
            },
        }

        # Build corresponding Switch sizes
        keys: List[int] = list(self.file_sizes.keys())
        for key in keys:
            sw_size = self.Convert_Save_Size(key, "switch", bool(self.file_sizes[key]["encrypted"]))
            self.file_sizes[sw_size] = {
                "encrypted": self.file_sizes[key]["encrypted"],
                "version": self.file_sizes[key]["version"],
                "platform": "switch",
            }

        # Initialize variables from given filepath
        self.sPath: str = filename
        with open(self.sPath, "rb") as f:
            self.data: bytes = f.read()
        self.file_size: int = len(self.data)

        self.file_type: str = "Unknown"
        self.file_version: int = 0
        self.encrypted_file: bool = False

        if self.file_size in self.file_sizes:
            meta = self.file_sizes[self.file_size]
            self.file_type = str(meta["platform"])
            self.file_version = int(meta["version"])
            self.encrypted_file = bool(meta["encrypted"])

    def Is_Encrypted(self) -> bool:
        return self.encrypted_file

    def Get_FileType(self) -> str:
        return self.file_type

    def Get_Version(self) -> int:
        return self.file_version

    def Get_FileSize(self) -> int:
        return self.file_size

    def Get_Path(self) -> str:
        return self.sPath

    def Convert_Save_Size(self, from_size: int, to_platform: str, to_encrypted: bool) -> int:
        if from_size not in self.file_sizes:
            print("Unknown file size " + hex(self.file_size) + ", cannot determine platform or encryption")
            return 0

        from_platform = str(self.file_sizes[from_size]["platform"])
        from_encrypted = bool(self.file_sizes[from_size]["encrypted"])

        if from_platform == to_platform and from_encrypted == to_encrypted:
            return from_size
        elif from_platform == to_platform and from_platform == "switch":
            return from_size - 0x80 if from_encrypted else from_size + 0x80
        elif from_platform == to_platform and from_platform == "pc":
            return from_size - 0xA8 if from_encrypted else from_size + 0xA8
        else:
            if from_encrypted and from_platform == "switch":
                return from_size + (0xC0 if to_encrypted else 0x18)
            elif from_encrypted and from_platform == "pc":
                return from_size - (0xC0 if to_encrypted else 0x140)
            elif (not from_encrypted) and from_platform == "switch":
                return from_size + (0x140 if to_encrypted else 0x98)
            else:
                return from_size - (0x18 if to_encrypted else 0x98)

    def Decrypt(self) -> None:
        if not self.encrypted_file:
            print("File " + self.sPath + " does not appear to be encrypted.")
            return
        if self.file_type != "switch":
            print("File " + self.sPath + " does not appear to be an encrypted Switch save file.")
            return

        print("Decrypting [" + self.sPath + "] ...")

        # Switch version has no extra md5 header; starts directly with encrypted #SAV section
        with open(self.sPath, "rb") as br:
            section1 = br.read(0x80)
            section1 = aes_ctr_crypt(self.Section1Key, self.Section1Counter, section1)

            file_bytes = self.data
            if len(file_bytes) != self.file_size:
                print(
                    "Error!  Encrypted file "
                    + self.sPath
                    + " size "
                    + str(len(file_bytes))
                    + " doesn't match the initialized size.  Expected size "
                    + str(self.file_size)
                )
                return

            if not (
                section1[0] == 0x23
                and section1[1] == 0x53
                and section1[2] == 0x41
                and section1[3] == 0x56
                and section1[4] == 0x00
            ):
                print("Failed at signature of first section.")
                return

            checksum1 = section1[0x14]
            checksum2 = section1[0x1B]
            checksum3 = section1[0x19]
            checksum4 = section1[0x18]
            checksum5 = section1[0x17]
            checksum6 = section1[0x16]
            checksum7 = section1[0x15]
            checksum8 = section1[0x1A]

            section2size = int.from_bytes(section1[0x7C:0x80], "little")
            section2 = br.read(section2size)

            # Checksum1
            temp = section1[0x5]
            for i in range(7):
                temp = (temp + section1[0x15 + i]) & 0xFF
            if checksum1 != temp:
                print(f"Checksum1 failed ({temp} != {checksum1}).")
                return

            # Checksum2
            temp = 0
            for i in range(section2size // 0x20):
                temp = (temp + section2[i * 0x20]) & 0xFF
            if checksum2 != temp:
                print(f"Checksum2 failed ({temp} != {checksum2}).")
                return

            # Checksum3
            temp = (section1[0x6C] + section1[0x70] + section1[0x74] + section1[0x78]) & 0xFF
            if checksum3 != temp:
                print(f"Checksum3 failed ({temp} != {checksum3}).")
                return

            # Checksum4
            temp = (section1[0x3C] + section1[0x40] + section1[0x44] + section1[0x48]) & 0xFF
            if checksum4 != temp:
                print(f"Checksum4 failed ({temp} != {checksum4}).")
                return

            # Checksum5
            temp = 0
            for i in range(8):
                temp = (temp + section1[0x4C + (i * 4)]) & 0xFF
            if checksum5 != temp:
                print(f"Checksum5 failed ({temp} != {checksum5}).")
                return

            # Checksum6
            temp = 0
            for i in range(8):
                temp = (temp + section1[0x1C + (i * 4)]) & 0xFF
            if checksum6 != temp:
                print(f"Checksum6 failed ({temp} != {checksum6}).")
                return

            # Checksum7
            temp = 0
            for i in range(14):
                temp = (temp + section1[0x6 + i]) & 0xFF
            if checksum7 != temp:
                print(f"Checksum7 failed ({temp} != {checksum7}).")
                return

            section2key = bytearray(0x20)
            section2ctr = bytearray(0x10)

            if (section1[0x5] & 4) > 0:
                section2key[:] = section1[0x4C:0x4C + 0x20]
                section2ctr[:] = section1[0x6C:0x6C + 0x10]
            else:
                section2key[:] = section1[0x1C:0x1C + 0x20]
                section2ctr[:] = section1[0x3C:0x3C + 0x10]

            section2 = aes_ctr_crypt(bytes(section2key), bytes(section2ctr), section2)

            if not (
                section2[0] == 0x23
                and section2[1] == 0x53
                and section2[2] == 0x41
                and section2[3] == 0x56
                and section2[4] == 0x00
            ):
                print("Failed at signature of second section.")
                return

            # Checksum8
            temp = 0
            for i in range(section2size // 0x20):
                temp = (temp + section2[i * 0x20]) & 0xFF
            if checksum8 != temp:
                print(f"Checksum8 failed ({temp} != {checksum8}).")
                return

            # Write outputs: derive base path safely (do not truncate blindly)
            base_no_ext, _ = os.path.splitext(self.sPath)
            newPath = base_no_ext if base_no_ext else self.sPath
            print("Decryption success")
            with open(newPath + ".switch.sav.dec", "wb") as wf:
                wf.write(section2)
            print("Switch Version: [" + newPath + ".switch.sav.dec]")

            # Create faux PC format decrypted file (proper size with padding and footer)
            pc_decrypted_size = self.Convert_Save_Size(self.file_size, "pc", False)
            pcfile = bytearray(pc_decrypted_size)

            # First 8 bytes same
            pcfile[0:8] = section2[0:8]
            # Save data shifted by 8
            pcfile[16:16 + (len(section2) - 8)] = section2[8:]

            # Add PC footer (from corresponding PC size based on encrypted flag)
            pc_encrypted_size = self.Convert_Save_Size(self.file_size, "pc", self.encrypted_file)
            pcfooter = self.file_sizes[pc_encrypted_size]["footer"]
            pcfile[-16:] = pcfooter

            print("PC Version: [" + newPath + ".pc.sav.dec]")
            with open(newPath + ".pc.sav.dec", "wb") as wf:
                wf.write(pcfile)

    def Encrypt(self) -> None:
        print("Encrypting [" + self.sPath + "] ...")

        section2 = bytearray(open(self.sPath, "rb").read())

        # Check for PC file and convert to switch decrypted layout
        if len(section2) == self.Convert_Save_Size(self.file_size, "pc", False):
            temp = bytearray(self.Convert_Save_Size(self.file_size, "switch", False))
            temp[0:16] = section2[0:16]
            temp[16:] = section2[24:24 + (len(temp) - 16)]
            section2 = temp

        # Build section1
        section1 = bytearray(get_random_bytes(0x80))
        section1[0x5] = 0x34

        # Checksum 8 over section2 (every 0x20th byte)
        section1[0x1A] = 0
        for i in range(len(section2) // 0x20):
            section1[0x1A] = (section1[0x1A] + section2[i * 0x20]) & 0xFF

        section2key = bytearray(0x20)
        section2ctr = bytearray(0x10)
        section2key[:] = section1[0x4C:0x4C + 0x20]
        section2ctr[:] = section1[0x6C:0x6C + 0x10]

        # CTR is symmetric; using decrypt here matches original
        section2 = bytearray(aes_ctr_crypt(bytes(section2key), bytes(section2ctr), bytes(section2)))

        # Checksums 7..2 based on header/section2
        section1[0x15] = 0
        for i in range(14):
            section1[0x15] = (section1[0x15] + section1[0x6 + i]) & 0xFF

        section1[0x16] = 0
        for i in range(8):
            section1[0x16] = (section1[0x16] + section1[0x1C + (i * 4)]) & 0xFF

        section1[0x17] = 0
        for i in range(8):
            section1[0x17] = (section1[0x17] + section1[0x4C + (i * 4)]) & 0xFF

        section1[0x18] = 0
        for i in range(4):
            section1[0x18] = (section1[0x18] + section1[0x3C + i * 4]) & 0xFF

        section1[0x19] = 0
        for i in range(4):
            section1[0x19] = (section1[0x19] + section1[0x6C + i * 4]) & 0xFF

        section1[0x1B] = 0
        for i in range(len(section2) // 0x20):
            section1[0x1B] = (section1[0x1B] + section2[i * 0x20]) & 0xFF

        # Checksum 1
        section1[0x14] = section1[0x5]
        for i in range(7):
            section1[0x14] = (section1[0x14] + section1[0x15 + i]) & 0xFF

        # Magic '#SAV' + 0x00
        section1[0x00:0x05] = b"#SAV\x00"

        # Write decrypted size at 0x7C
        dec_size = self.Convert_Save_Size(self.file_size, "switch", False)
        section1[0x7C:0x80] = struct.pack("<I", dec_size)

        # Encrypt header
        section1 = bytearray(aes_ctr_crypt(self.Section1Key, self.Section1Counter, bytes(section1)))

        # Assemble full encrypted file
        enc_size = self.Convert_Save_Size(self.file_size, "switch", True)
        completeFile = bytearray(enc_size)
        completeFile[0:0x80] = section1
        completeFile[0x80:0x80 + len(section2)] = section2

        # Write output as <input>.enc (do not modify original name)
        out_path = self.sPath + ".enc"
        print("Encryption success")
        with open(out_path, "wb") as wf:
            wf.write(completeFile)
        print("[" + out_path + "]")


def _is_decrypted_file(path: str) -> bool:
    try:
        with open(path, "rb") as f:
            header = f.read(4)
        return header == b"#SAV"
    except Exception:
        return False


def main(file_path: str) -> None:
    """Convenience entry point for GUI: auto-detect decrypt/encrypt and run."""
    if not os.path.isfile(file_path):
        print(f"Input not found: {file_path}")
        return
    tool = Xv2SavFile(file_path)
    # Auto: if looks decrypted, encrypt; else decrypt.
    if file_path.endswith((".switch.sav.dec", ".pc.sav.dec", ".sav.dec")) or _is_decrypted_file(file_path):
        tool.Encrypt()
    else:
        tool.Decrypt()


def main_cli(argv: List[str]) -> int:
    parser = argparse.ArgumentParser(description="XV2 Switch save decrypt/encrypt tool")
    parser.add_argument("file", help="Path to the Switch save or decrypted save")
    parser.add_argument("mode", nargs="?", choices=["auto", "decrypt", "encrypt"], default="auto",
                        help="Operation mode (default: auto)")
    args = parser.parse_args(argv)

    if not os.path.isfile(args.file):
        print(f"Input not found: {args.file}")
        return 2

    tool = Xv2SavFile(args.file)

    try:
        mode = args.mode
        if mode == "auto":
            if args.file.endswith((".switch.sav.dec", ".pc.sav.dec", ".sav.dec")) or _is_decrypted_file(args.file):
                mode = "encrypt"
            else:
                mode = "decrypt"

        if mode == "decrypt":
            tool.Decrypt()
        else:
            tool.Encrypt()
        return 0
    except Exception as ex:
        print(f"Error: {ex}")
        return 1


if __name__ == "__main__":
    sys.exit(main_cli(sys.argv[1:]))


