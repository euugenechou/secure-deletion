#!/bin/sh

make
sudo mount -o loop ~/Desktop/holepunch/jessie.img /mnt/jessie
sudo cp ggm_prf.ko /mnt/jessie
sudo cp pprf.ko /mnt/jessie
sudo cp pprf-tree.ko /mnt/jessie
sudo umount /mnt/jessie
