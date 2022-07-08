#!/usr/bin/env bash

# Run Bonnie++ with 512 files for creation/deletion.
# Set -r to installed RAM. Bonnie++ uses RAM*2 for file size.
# User root:root for running in QEMU.
#time bonnie++ -d . -r 16000 -n 512 -u root:root > perf.txt
time bonnie++ -d . -r 16000 -n 512 > perf.txt

# Generate HTML report.
tail -1 perf.txt | bon_csv2html > perf.html

