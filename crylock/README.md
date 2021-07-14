# crylock_analysis

This repository contains analysis scripts, YARA rules, and additional IoCs related to the blog post [LOCKDATA Auction – Another leak marketplace showing the recent shift of ransomware operators](https://www.telekom.com/en/blog/group/article/lockdata-auction-631300).

- `crylock_20210706.yar`: several YARA rules to detect CryLock binaries and ransom notes
- `crylock_hashes.csv`: list of hashes that match the rules from `crylock_20210706.yar` as well as the rule `RAN_CryLock_Oct_2020_1` found in [https://github.com/StrangerealIntel/DailyIOC](https://github.com/StrangerealIntel/DailyIOC/blob/master/2020-10-15/Crylock/RAN_CryLock_Oct_2020_1.yar). Note that `CryLock_Search_Keys` and `CryLock_Search_Keys_Zip` are not real rules but just convenience tags to list samples.
