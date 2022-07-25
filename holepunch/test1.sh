#!/bin/bash

printf "\n Remember to lower the refresh interval to 10 for this test ...\n\n"
sleep 2

insmod /holepunch/kernel_module/dm-holepunch.ko
printf "ooo\no\no" | holepunch create /dev/sdb1 5
printf "ooo\no" | holepunch open /dev/sdb1 test
mkfs.ext4 /dev/mapper/holepunch
mount /dev/mapper/holepunch /mnt/home
cd /mnt/home

fname=""
contents=""
numfiles=500

for ((i=0; i<$numfiles; i++))
do
    printf -v fname "hello%03d" "$i"
    printf -v contents "hello from %03d" "$i"
    echo "$contents" > "$fname"
done

sync
echo "1" > /proc/sys/vm/drop_caches
ls

for ((i=0; i<$numfiles-2; i++))
do
    # sleep 1
    printf -v fname "hello%03d" "$i"
    printf "Deleting $fname...\n"
    j=i+1
    rm "$fname"
    # printf -v fname "hello%03d" "$((i + 1))"
    # cat "$fname"
done

# cd ..
# umount home
# holepunch close test

# printf "ooo\no" | holepunch open /dev/sdb1 test
# mount /dev/mapper/holepunch /mnt/home
# cd /mnt/home

sleep 1
ls
printf -v fname "hello%03d" "$((numfiles - 2))"
cat "$fname"
printf -v fname "hello%03d" "$((numfiles - 1))"
cat "$fname"
# cat hi
# cat bar
# cat baz