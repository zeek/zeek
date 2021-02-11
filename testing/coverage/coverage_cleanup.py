#!/usr/bin/env python3

import sys

if len(sys.argv) != 2:
    print("Expected one argument containing the file to clean")
    sys.exit(-1)

with open(sys.argv[1], 'r') as f:

    files = {}
    cur_file = ''
    lines = f.readlines()

    for line in lines:

        if line == 'end_of_record':
            cur_file = ''
            continue

        parts = line.split(':', 1)
        if parts[0] == 'SF':
            cur_file = parts[1].strip()
            while cur_file.find('src/zeek/') != -1:
                cur_file = cur_file.replace('src/zeek/', 'src/', 1)

            if cur_file not in files:
                files[cur_file] = {}
        elif parts[0] == 'DA':
            da_parts = parts[1].split(',')
            line = int(da_parts[0])
            count = int(da_parts[1])

            if files[cur_file].get(line, 0) == 0:
                files[cur_file][line] = count

    for name in files:

        print('TN:')
        print('SF:{}'.format(name))

        das = list(files[name].keys())
        das.sort()

        for da in das:
            print('DA:{},{}'.format(da, files[name][da]))
        print('end_of_record')
