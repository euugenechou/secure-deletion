#!/usr/bin/env bash

ROOT="${HOLEPUNCH_ROOT:-$HOME/secure-deletion/holepunch}"
KMOD_ROOT="$ROOT/kernel_module"
EXEC_ROOT="$ROOT/holepunch-userland"

KMOD="$KMOD_ROOT/dm-holepunch.ko"
EXEC="$EXEC_ROOT/build/holepunch"

DEVICE="${HOLEPUNCH_DEVICE:-/dev/vdb}"
MOUNT="${HOLEPUNCH_MOUNT:-/mnt/home}"

DM_NAME=test

umount $MOUNT
mkdir -p $MOUNT

if lsmod | grep dm_holepunch; then
    rmmod -f dm_holepunch
fi

insmod $KMOD

printf "ooo\no\no" | $EXEC create $DEVICE 5
printf "ooo\no" | $EXEC open $DEVICE $DM_NAME
mkfs.ext4 /dev/mapper/$DM_NAME
mount /dev/mapper/$DM_NAME $MOUNT
cd $MOUNT

echo hello > hi
echo foo > bar
echo barbar > baz
sync
cat hi
cat bar
cat baz
rm hi
cd ..
umount $MOUNT

mount /dev/mapper/$DM_NAME $MOUNT
cd $MOUNT
ls
cat bar
cat baz
echo yellow > hi
cd ..
umount $MOUNT
$EXEC close $DM_NAME

# printf "ooo\no" | $EXEC open $DEVICE $DM_NAME
# mount /dev/mapper/$DM_NAME $MOUNT
# cd $MOUNT
# cat hi
# cat bar
# cat baz
# cd ..
# umount $MOUNT
# $EXEC close $DM_NAME
