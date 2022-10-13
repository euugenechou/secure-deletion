#!/bin/bash

printf "\n Remember to lower the refresh interval to 10 for this test ...\n\n"
sleep 2

insmod /root/dm-holepunch.ko
printf "ooo\no\no" | holepunch create /dev/sdb1 5
printf "ooo\no" | holepunch open /dev/sdb1 test
mkfs.ext4 /dev/mapper/holepunch
mount /dev/mapper/holepunch /mnt/home
cd /mnt/home

fname=""
contents=""
numfiles=400

echo "Numfiles = " $numfiles

for ((i=0; i<$numfiles; i++))
do
    printf -v fname "hello%04d" "$i"
    printf -v contents "hello from %04d" "$i"
    echo "$contents" > "$fname"
done

sync
echo "1" > /proc/sys/vm/drop_caches

for ((i=0; i<$numfiles-2; i++))
do
    # sleep 1
    printf -v fname "hello%04d" "$i"
    printf "Deleting $fname...\n"
    rm "$fname"
done

# sleep 0
ls
printf -v fname "hello%04d" "$((numfiles - 2))"
cat "$fname"
printf -v fname "hello%04d" "$((numfiles - 1))"
cat "$fname"

cd /mnt
umount home
# slneep 0
holepunch close test
printf "ooo\no" | holepunch open /dev/sdb1 test
