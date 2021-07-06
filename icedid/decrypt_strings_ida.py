import struct

from malduck import xor
from malduck.bits import rol, ror

import ida_bytes


def generate_round_key(seed):
    # .text:0000000180015B00 decrypt_string_shifting proc near       ; CODE XREF: decrypt_string+65↑p
    # .text:0000000180015B00                                         ; sub_18000A56C+117↑p ...
    # .text:0000000180015B00                 lea     eax, [rcx+2E59h]
    # .text:0000000180015B06                 ror     eax, 1
    # .text:0000000180015B08                 ror     eax, 1
    # .text:0000000180015B0A                 ror     eax, 2
    # .text:0000000180015B0D                 xor     eax, 151Dh
    # .text:0000000180015B12                 rol     eax, 2
    # .text:0000000180015B15                 rol     eax, 1
    # .text:0000000180015B17                 retn
    # .text:0000000180015B17 decrypt_string_shifting endp
    eax = seed + 0x2E59
    eax = ror(eax, 1)
    eax = ror(eax, 1)
    eax = ror(eax, 2)
    eax = struct.unpack("I", xor(struct.pack("I", eax)[0:2], struct.pack("H", 0x151D)) + struct.pack("I", eax)[2:4])[0]
    eax = rol(eax, 2)
    eax = rol(eax, 1)
    return eax


def decrypt_string(offset):
    b = ida_bytes.get_bytes(offset, 0x200)
    str_size = struct.unpack("H", xor(b[4:6], b[0:2]))[0]
    xor_key_index = 6
    decrypted_string = ""

    seed = ida_bytes.get_dword(offset)
    for current_offset in range(str_size):
        seed = generate_round_key(seed)
        current_dec_chr = b[xor_key_index] ^ (seed & 0xFF)
        xor_key_index += 1
        decrypted_string += chr(current_dec_chr)
    return decrypted_string


# This is an example script that implements the core decryption
# algorithm of current IcedID samples.
print(decrypt_string(0x1800208B8))
