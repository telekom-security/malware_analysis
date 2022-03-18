rule Vatet_Loader_Rufus_Backdoor : defray777
{
	meta:
        author = "Thomas Barabosch, Deutsche Telekom Security"
        twitter = "https://twitter.com/DTCERT"
		date = "2022-03-18"
        description = "Detects backdoored Rufus with Vatet Loader of Defray777"
        reference1 = "https://github.com/pbatard/rufus"
        reference2 = "https://unit42.paloaltonetworks.com/vatet-pyxie-defray777"
        sharing = "TLP:WHITE"
        hash_1 = "c9c1caae50459896a15dce30eaca91e49e875207054d98e32e16a3e203446569"
        hash_2 = "0cb8fc89541969304f3bf806e938452b36348bdd0280fc8f4e9221993e745334"
        in_memory = "False"
	strings:
        /*
            0x4d0714 660FF8C1                      psubb xmm0, xmm1
	        0x4d0718 660FEFC2                      pxor xmm0, xmm2
	        0x4d071c 660FF8C1                      psubb xmm0, xmm1
	    */
        $payload_decryption = { 66 0F F8 C1 66 0F EF C2 66 0F F8 C1 }
        $mz = "MZ" ascii
        $rufus = "https://rufus.ie/" ascii
	condition:
        $mz at 0
        and $payload_decryption
        and $rufus
}
