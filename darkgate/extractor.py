import argparse
import base64
import binascii
import json
import logging
import magic
import re
import subprocess
import tempfile
import zlib

CONFIG_ALPHABET_SPACER = bytes.fromhex("FF FF FF FF 40 00 00 00")
CONFIG_ALPHABET_REGEX = re.compile(
    CONFIG_ALPHABET_SPACER
    + rb"([^\0]{64})\0{4}"
    + CONFIG_ALPHABET_SPACER
    + rb"([^\0]{64})\0{4}"
)
PE_START_BYTES = bytes.fromhex("4D5A50000200000004000F00FFFF00")
AU3_MAGIC_BYTES = b"AU3!EA06"
PE_CHARACTERISTIC_STRING = b"__padoru__"
REGEX_CONFIG_CANDIDATES = rb"[A-Za-z0-9+/=]{10,}"


# =====================================================================
# Custom base64 decoding as implemented by rivitna:
# https://github.com/rivitna/Malware2/blob/main/DarkGate/dg_dec_data.py
def base64_decode_block(block, encode_table):
    if len(block) < 2:
        raise ValueError("Base64 decode error.")
    n = 0
    for i in range(4):
        n <<= 6
        if i < len(block):
            b = encode_table.find(block[i])
            if b < 0:
                raise ValueError("Base64 invalid char (%02X)." % block[i])
            n |= b

    dec_block = bytes([(n >> 16) & 0xFF, (n >> 8) & 0xFF])
    if len(block) >= 4:
        dec_block += bytes([n & 0xFF])

    return dec_block


def base64_decode(data, encode_table):
    dec_data = b""
    for block in (data[i : i + 4] for i in range(0, len(data), 4)):
        dec_data += base64_decode_block(block, encode_table)

    return dec_data


# =====================================================================


class DarkGateUnpacker:
    def __init__(self, payload: bytes):
        self.payload = payload

    def unpack(self) -> bytes:
        raise NotImplementedError("Must be implemented by child class.")


class DarkGateAU3Unpacker(DarkGateUnpacker):
    def _decrypt_payload(self, payload: bytes, xor_key: int) -> bytes:
        decoded = base64.b64decode(payload)
        decrypted = bytes(b ^ xor_key for b in decoded)
        return decrypted

    def _unpack_au3_payload_legacy(self) -> bytes:
        try:
            splitted = self.payload.split(b"|")
            xor_key = "a" + splitted[1][1:9].decode()
            final_xor_key = len(xor_key)
            for char in xor_key:
                final_xor_key ^= ord(char)
            final_xor_key = ~final_xor_key
            final_xor_key &= 255
            payload = self._decrypt_payload(splitted[2], final_xor_key)
            return payload
        except UnicodeDecodeError:
            return None
        except binascii.Error:
            return None

    def _unpack_au3_payload_new(self) -> bytes:
        try:
            splitted = self.payload.split(b"|")
            key = splitted[1]
            sorted_key = bytes(sorted(key))
            if (
                len(splitted[1]) != 64
                or sorted_key
                != b"+0123456789=ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
            ):
                logging.info("No usable custom base64 alphabet found in AU3 file.")
                return None
            else:
                logging.info(f"AU3 file uses custom base64 alphabet: {key.decode()}")
                return base64_decode(splitted[2], key)
        except binascii.Error:
            return None

    def _check_result(self, result: bytes) -> bool:
        return result.startswith(PE_START_BYTES) and PE_CHARACTERISTIC_STRING in result

    def unpack(self) -> bytes:
        payload = self._unpack_au3_payload_legacy()
        if payload and self._check_result(payload):
            return payload

        payload = self._unpack_au3_payload_new()
        if payload and self._check_result(payload):
            return payload

        return None


class DarkGateMSIUnpacker(DarkGateUnpacker):
    def unpack(self) -> bytes:
        with tempfile.NamedTemporaryFile("wb") as f:
            f.write(self.payload)
            f.flush()
            try:
                bin_7z = subprocess.check_output(["which", "7z"]).decode().strip()
                return subprocess.check_output(
                    [bin_7z, "e", "-so", f.name, "Binary.bz.WrappedSetupProgram"]
                )

            except subprocess.CalledProcessError:
                logging.error("Unpacking of MSI file failed")
                return None


class DarkGateCABUnpacker(DarkGateUnpacker):
    def unpack(self) -> bytes:
        with tempfile.NamedTemporaryFile("wb") as f:
            f.write(self.payload)
            f.flush()
            try:
                bin_7z = subprocess.check_output(["which", "7z"]).decode().strip()
                return subprocess.check_output(
                    f'{bin_7z} e -so {f.name} "*.au3"', shell=True
                )
            except subprocess.CalledProcessError:
                logging.error("Unpacking of CAB file failed")
                return None


class DarkGateRecursiveUnpacker(DarkGateUnpacker):
    def unpack(self) -> bytes:
        continue_unpacking = True
        while continue_unpacking:
            mime_type = magic.from_buffer(self.payload, mime=True)
            if "application/x-msi" in mime_type:
                logging.info(f"Found MSI payload. Trying to unpack.")
                self.payload = DarkGateMSIUnpacker(self.payload).unpack()
                continue_unpacking = self.payload is not None
            elif "application/vnd.ms-cab-compressed" in mime_type:
                logging.info(f"Found CAB payload. Trying to unpack.")
                self.payload = DarkGateCABUnpacker(self.payload).unpack()
                continue_unpacking = self.payload is not None
            elif "text/plain" in mime_type and AU3_MAGIC_BYTES in self.payload:
                logging.info(f"Found AU3 payload. Trying to unpack.")
                self.payload = DarkGateAU3Unpacker(self.payload).unpack()
                continue_unpacking = self.payload is not None
            elif (
                "application/vnd.microsoft.portable-executable" in mime_type
                and self.payload.startswith(PE_START_BYTES)
            ):
                logging.info(f"Found PE file. Unpacking finished")
                return self.payload
            else:
                continue_unpacking = False
        return None


class DarkGateConfigExtractor:
    def __init__(self, payload: bytes):
        self.payload = payload
        self.result = {}
        self.config_flag_mapping = {
            "0": "c2_port",
            "1": "startup_persistence",
            "2": "rootkit",
            "3": "anti_vm",
            "4": "min_disk",
            "5": "check_disk",
            "6": "anti_analysis",
            "7": "min_ram",
            "8": "check_ram",
            "9": "check_xeon",
            "10": "internal_mutex",
            "11": "crypter_rawstub",
            "12": "crypter_dll",
            "13": "crypter_au3",
            "15": "crypto_key",
            "16": "c2_ping_interval",
            "17": "anti_debug",
            "23": "username",
        }

    def _get_config_alphabets(self) -> tuple[bytes]:
        config_alphabet_match = CONFIG_ALPHABET_REGEX.search(self.payload)
        if config_alphabet_match:
            logging.info(
                f"Custom base64 alphabets for configuration extraction found: {config_alphabet_match.groups()}"
            )
            return config_alphabet_match.groups()
        else:
            logging.info(
                "Could not find the custom base64 alphabets for configuration extraction."
            )
            return None, None

    def _decode_strings(self, alphabet: bytes):
        result = []
        string_candidates = re.findall(
            rb"[" + re.escape(bytes(sorted(alphabet))) + rb"]{5,}", self.payload
        )
        for s in string_candidates:
            try:
                # Try to decode each string candidate with each alphabet candidate
                decoded = base64_decode(s, alphabet).decode()
                decoded_length = len(decoded)
                ascii_length = len(decoded.encode("ascii", "ignore"))
                # Rather simple check to sort out garbage strings
                if decoded_length == ascii_length:
                    result.append(decoded)
            except UnicodeDecodeError:
                pass
            except ValueError:
                pass
        self.result["strings"] = result

    def _parse_config_value(self, value: str) -> bool | int | str:
        if value == "No":
            return False
        elif value == "Yes":
            return True
        elif value.isnumeric():
            return int(value)
        else:
            return value

    def _parse_config_string(self, value: str):
        for item in re.findall(r"(\d+)=(\w+)", value):
            if item[0] in self.config_flag_mapping:
                self.result[
                    self.config_flag_mapping[item[0]]
                ] = self._parse_config_value(item[1])
            else:
                self.result[f"flag_{item[0]}"] = self._parse_config_value(item[1])

    def _parse_c2_string(self, value: str):
        split_string = value.strip("\0").strip().split("|")
        if len(split_string) > 1:
            split_string.remove("")
            self.result["c2_servers"] = split_string

    def _decode_config(self, alphabet: bytes):
        for match in re.findall(REGEX_CONFIG_CANDIDATES, self.payload):
            try:
                decoded = base64_decode(match, alphabet)
                if re.match(rb"^https?:\/\/", decoded):
                    self._parse_c2_string(decoded.decode())
                    continue
                elif b"1=Yes" in decoded or b"1=No" in decoded:
                    self._parse_config_string(decoded.decode())
                    continue
                else:
                    inflated = zlib.decompress(decoded).decode()
                    if "1=Yes" in inflated or "1=No" in inflated:
                        self._parse_config_string(inflated)
            except zlib.error:
                pass
            except ValueError:
                pass

    def extract(self) -> dict:
        string_alphabet, config_alphabet = self._get_config_alphabets()
        if string_alphabet:
            self._decode_strings(string_alphabet)
        if config_alphabet:
            self._decode_config(config_alphabet)
        return self.result


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("file")
    parser.add_argument(
        "-s",
        "--strings",
        required=False,
        action="store_true",
        help="Output decrypted strings",
    )
    parser.add_argument(
        "-d",
        "--debug",
        required=False,
        action="store_true",
        help="Provide debug log output",
    )
    args = parser.parse_args()
    if args.debug:
        level = logging.INFO
    else:
        level = logging.ERROR
    logging.basicConfig(format="[%(levelname)s] %(message)s", level=level)
    logging.info("Starting Telekom Security DarkGate Extractor")
    with open(args.file, "rb") as f:
        result = DarkGateRecursiveUnpacker(f.read()).unpack()
        if result:
            config_result = DarkGateConfigExtractor(result).extract()
            if config_result:
                if not args.strings:
                    config_result.pop("strings")
                print(json.dumps(config_result, sort_keys=True, indent=4))
            else:
                logging.error("Failed to extract configuration.")
        else:
            logging.error("Could not find any usable payload.")
