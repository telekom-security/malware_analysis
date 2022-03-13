rule win_systembc_20220311 {
    meta:
        author = "Thomas Barabosch, Deutsche Telekom Security"
        twitter = "https://twitter.com/DTCERT"
        description = "Detects unpacked SystemBC module"
        date = "20220311"
        sharing = "TLP:WHITE"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.systembc"
        reference_1 = "https://twitter.com/Cryptolaemus1/status/1502069552246575105"
        reference_2 = "https://medium.com/walmartglobaltech/inside-the-systembc-malware-as-a-service-9aa03afd09c6"
        hash_1 = "c926338972be5bdfdd89574f3dc2fe4d4f70fd4e24c1c6ac5d2439c7fcc50db5"
        in_memory = "True"
    strings:
        $sx1 = "-WindowStyle Hidden -ep bypass -file" ascii
        $sx2 = "BEGINDATA" ascii
        $sx3 = "GET %s HTTP/1.0" ascii
        /*
        $s1 = "TOR:" ascii
        $s2 = "PORT1:" ascii
        $s3 = "HOST1:" ascii 
        */
        $s5 = "User-Agent:" ascii
        /* $s6 = "powershell" ascii */
        $s8 = "ALLUSERSPROFILE" ascii
    condition:
        ( uint16(0) == 0x5a4d and filesize < 30KB and 2 of ($sx*) ) or all of them
}
