import argparse
import hashlib
import struct
from malduck.bits import ror


def change_endian_of_str(s):
    if len(s) == 8:
        return s[6:] + s[4:6] + s[2:4] + s[:2]
    elif len(s) == 12:
        return s[2:4] + s[:2] + s[10:] + s[8:10] + s[6:8] + s[4:6]
    else:
        return s[2:] + s[:2]


def build_reg_key_guid(h):
    # {%0.8X-%0.4X-%0.4X-%0.4X-%0.4X%0.8X}
    return '{' + f'{change_endian_of_str(h[:8])}-{change_endian_of_str(h[8:12])}-{change_endian_of_str(h[12:16])}-{change_endian_of_str(h[16:20])}-{change_endian_of_str(h[20:])}' + '}'


def compute_registry_key(key_name, bot_id):
    temp_key = 0x0
    for c in key_name:
        temp_key = (ord(c) + ror(temp_key, 0xD)) & 0xFFFFFFFF

    xored_bot_id = temp_key ^ bot_id

    md5 = hashlib.md5(key_name.encode())
    md5.update(struct.pack("I", xored_bot_id))
    hashed_key_name = md5.hexdigest().upper()
    final_reg_key = build_reg_key_guid(hashed_key_name)
    return final_reg_key


def fnv32a(string):
    hval = 0x811c9dc5
    fnv_32_prime = 0x01000193
    uint32_max = 2 ** 32
    for s in string:
        hval = hval ^ ord(s)
        hval = (hval * fnv_32_prime) % uint32_max
    return hval


def compute_bot_id(sid, second_value):
    tmp = fnv32a(sid) ^ 0x87EA50BD
    bot_id = struct.unpack(">I", struct.pack(">I", tmp))[0]
    bot_id_negated = ~tmp + (1 << 32)
    return bot_id, bot_id_negated


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("SID",
                        help="SID of local account, e.g. S-1-5-21-1984500107-304187221-49949575")
    args = parser.parse_args()
    return args


def main():
    args = parse_args()
    second_value = b'\x91\x06\x2d\x3c'
    bot_id = compute_bot_id(args.sid, second_value)
    print(f'The bot id for SID {args.sid} is {hex(bot_id[0])} and {hex(bot_id[1])} (negated)')

    # hardcoded in binary, future update maybe required
    REGISTRY_KEYS = ["{0ccac395-7d1d-4641-913a-7558812ddea2}",
                     "{d65f4087-1de4-4175-bbc8-f27a1d070723}",
                     "{e3f38493-f850-4c6e-a48e-1b5c1f4dd35f}"]

    for k in REGISTRY_KEYS:
        print(k, '=>', compute_registry_key(k, bot_id[1]))


if __name__ == '__main__':
    main()
