#!/usr/bin/env bash

usage() {
  printf "Usage: $0 -n [num] -d [dirs]\n\n";
  printf "[num] : Number of files to create/delete\n"
  printf "[dirs] : Number of subdirectories to split files across (default: 0)\n\n"
  exit 1
}

if [ "$#" -ne 4 ]; then
  usage
fi

while [ "$1" != "" ]; do
  case $1 in
      -h|--help)
	usage
	;;
      -n|--num) 
        FILES=$2
        shift
        ;;  
      -d|--dirs)
        DIRS=$2
        shift
        ;;
      *)  
        break
        ;;  
  esac
  shift
done

printf "[+] Running Bonnie++ with $FILES files across $DIRS sub-directories...\n"

# Run Bonnie++ with 512*1024 files for creation/deletion.
# Set -r to installed RAM. Bonnie++ uses RAM*2 for file size.
# User root:root for running in QEMU.
#time bonnie++ -d . -r 16000 -n 512 -u root:root > perf.txt
time bonnie++ -d . -r 16000 -n $FILES:$DIRS > perf.txt

# Generate HTML report.
tail -1 perf.txt | bon_csv2html > perf.html

# View report.
firefox perf.html &
