import sys
import hashlib
import json

from androguard.misc import AnalyzeDex

BLACKLIST_URLS = ['https://www.googleapis.com/auth/games',
                  'https://plus.google.com/'
                  ]


def store_config(config, sample_path):
    if sample_path.endswith('classes.dex'):
        sample_path = sample_path.replace('classes.dex', 'teabot_config.json')
    else:
        sample_path = sample_path + '_teabot_config.json'

    with open(sample_path, 'w') as fp:
        json.dump(config, fp)


def is_blacklisted_url(s):
    for d in BLACKLIST_URLS:
        if d == s:
            return True
    return False


def get_sha256(dex_file):
    sha256_hash = hashlib.sha256()
    with open(dex_file, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()


def extract(dex_file):
    print("Extracting config...")
    hash_sha256 = get_sha256(dex_file)
    config = {"sha256": hash_sha256}

    print('Analyzing Dex...')
    h, d_dalvik, dx_analysis = AnalyzeDex(dex_file)
    all_strings = [x.get_value() for x in dx_analysis.find_strings()]
    print(f'Found {len(all_strings)} strings.')

    if 'kill_bot' not in all_strings:
        print('Not Teabot, aborting')
        return {}

    cc_urls = []
    for s in all_strings:
        if s.startswith('http') and not is_blacklisted_url(s):
            print(f'Found possible CC URL: {s}')
            cc_urls.append(str(s))

    if cc_urls:
        config['cc_urls'] = cc_urls

    return config


sample = sys.argv[1]
config = extract(sample)
if config:
    print(config)
    store_config(config, sample)
