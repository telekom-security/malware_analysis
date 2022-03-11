# Author: Thomas Barabosch, Deutsche Telekom Security
# Date: 2022-03-11
# Sharing: TLP:WHITE
# https://twitter.com/DTCERT
# https://github.com/telekom-security/malware_analysis
#
# Find unpacked samples on VirusTotal with this VT Intelligence Query:
# 'content:"BEGINDATA" tag:peexe size:30KB-'

import json
import re
import sys


def store_config(config, sample_path):
    sample_path = sample_path + '_systembc_config.json'

    with open(sample_path, 'w') as fp:
        json.dump(config, fp)


def extract_ascii_strings(data, min_len=4):
    # taken from https://github.com/kevthehermit/RATDecoders/blob/master/malwareconfig/fileparser.py
    string_list = []
    regexp = b'[%s]{%d,}' % (b" !\"#\$%&\'\(\)\*\+,-\./0123456789:;<=>\?@ABCDEFGHIJKLMNOPQRSTUVWXYZ\[\]\^_`abcdefghijklmnopqrstuvwxyz\{\|\}\\\~\t", min_len)
    pattern = re.compile(regexp)
    for s in pattern.finditer(data):
        string_list.append(s.group().decode())
    return string_list


def parse_strings(file_data):
    ports = []
    hosts = []
    tor = []
    for s in extract_ascii_strings(file_data):
        if 'PORT' in s:
            tmp = s.split(':')[1].strip()
            if tmp:
                ports.append(int(tmp))
        elif 'HOST' in s:
            tmp = s.split(':')[1].strip()
            if tmp:
                hosts.append(tmp)
        elif 'TOR' in s:
            tmp = s.split(':')[1].strip()
            if tmp:
                tor.append(tmp)
    return hosts, ports, tor


def extract(sample_path):
    with open(sample_path, 'rb') as f:
        file_data = f.read()
        hosts, ports, tor = parse_strings(file_data)

        if hosts or ports or tor:
            config = {}
            if ports:
                config['ports'] = ports
            if hosts:
                config['hosts'] = hosts
            if tor:
                config['tor'] = tor
            return config
    return None


def main():
    if len(sys.argv) != 2:
        print('Usage: extract_systembc.py PATH_TO_SAMPLE')
        sys.exit(1)

    sample_path = sys.argv[1]
    config = extract(sample_path)
    if config:
        print(f'Extracted config: {config}')
        store_config(config, sample_path)
    else:
        print('Could not extract config.')


if __name__ == '__main__':
    main()
