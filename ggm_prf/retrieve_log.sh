#!/bin/sh

sudo mount -o loop ~/Desktop/holepunch/jessie.img /mnt/jessie
sudo cp /mnt/jessie$1 .
sudo umount /mnt/jessie

