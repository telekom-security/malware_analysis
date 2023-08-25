import base64

print("""rule DarkGateAU3EmbeddedPEFile
{
    strings:""")

for xor_key in range(256):
    encoded = bytes(b ^ xor_key for b in bytes.fromhex("4D5A50000200000004000F00FFFF00"))
    b64 = base64.b64encode(encoded)
    print(f"        $x{xor_key} = \"{b64.decode()}\"")

print("""        $au3 = "AU3!EA06"

    condition:
        $au3 and 1 of ($x*)
}""")

