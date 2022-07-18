#!/bin/sh

insmod /holepunch/kernel_module/dm-holepunch.ko
echo "ooo\no\no" | holepunch create /dev/sdb1 5
echo "ooo\no" | holepunch open /dev/sdb1 test
mkfs.ext4 /dev/mapper/holepunch
mount /dev/mapper/holepunch /mnt/home
cd /mnt/home

echo hello > hi
echo foo > bar
echo barbar > baz
sync
cat hi
cat bar
cat baz
rm hi
cd ..
umount home

mount /dev/mapper/holepunch /mnt/home
cd /mnt/home
ls
cat bar
cat baz
echo yellow > hi
cd ..
umount home
holepunch close test

echo "ooo\no" | holepunch open /dev/sdb1 test
mount /dev/mapper/holepunch /mnt/home
cd /mnt/home
cat hi
cat bar
cat baz