# Flubot / Teabot

This repository contains analysis scripts, YARA rules, and additional IoCs related to the blog post [Flubot's Smishing Campaigns under the Microscope](https://www.telekom.com/en/blog/group/article/flubot-under-the-microscope-636368).

- `hashes.csv`: list of hashes of Flubot and Teabot as distributed by the Flubot botnet
- `flubot.yar`: YARA rules to detect unpacked Flubot samples
- `teabot.yar`: YARA rules to detect unpacked Teabot samples
- `teabot_extractor.py`: extracts IOCs from unpacked Teabot samples
