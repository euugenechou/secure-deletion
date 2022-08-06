# Benchmarking and Testing Holepunch

We walk through the steps for setting up a testing environment for Holepunch and/or Eraser. 
These steps have been tested on a Windows 10 machine with Intel VT-x support, and use an Ubuntu 22.04 Virtual Machine running in VirtualBox as a host.

##### Install Dependencies
```
sudo apt update
sudo apt install qemu-kvm
sudo apt install debootstrap
sudo apt install swtpm
```

##### Building the Disk Image
Once you have installed the necessary dependencies you can extract the tarball found in this directory.

`tar -xvf benchmarking.tar.gz`

This directory contains all of the necessary files for testing and running the latest version of Holepunch (and Eraser). We first build a disk image with a minimal Debian Jessie userspace and Holepunch kernel module. 

`sudo ./setup_drive.sh`

This outputs a 4GB `benchmark.img` disk image that you can boot into with QEMU. 

You'll also want to setup another drive that will be used by Holepunch to store encrypted file system content. 

`dd if=/dev/zero of=encrypted.img bs=1 seek=64GB count=1`

This outputs a 64GB drive `encrypted.img` that will get used by Holepunch. Feel free to make the drive bigger or smaller depending on your tests.   

##### Starting QEMU

You might wish to edit the `start_qemu.sh` script to customize your QEMU configuration before spinning up the test machine. The script defaults to use KVM and allocates 2GB of RAM. 

`./start_qemu.sh`

Note that by default the script boots QEMU in non-graphical mode. In non-graphical mode, you can use `Ctrl + X` then `A` to terminate the QEMU instance. 

##### Setting up the QEMU 

Log in to the QEMU machine as `root` (no password) and install the required software packages:

`./install_pkgs.sh`

Once the packages have been installed you are ready to build and install Holepunch.

##### Installing Holepunch

First, install the Holepunch kernel module on the QEMU instance using:

`insmod dm-holepunch.ko`

Then install the Holepunch userspace tool:

`cd holepunch-userland`
`make install`

You now have Holepunch installed and ready to go!

##### Setting up the TPM

To use Holepunch (or Eraser) we will need to make sure that the TPM is setup with an owner password.

`tpm_createek`
`tpm_takeownership`

When prompted, enter a memorable password for unlocking and using the TPM. 

##### Setting up a Holepunch Device

The `encrypted.img` drive is located at `/dev/sdb` which we will use for testing. 

Create a partition on the `encrypted.img` drive:

```
fdisk /dev/sdb
> n
> (default options)
```

Then create a Holepunch instance on the new partition:

`holepunch create /dev/sdb 5`

Note that this initialization step may take awhile depending on the size of `encrypted.img`.

*(The `5` parameter specifies which NVRAM index of the TPM chip to store the Holepunch master password.*

Then you can open the Holepunch instance:

`holepunch open /dev/sdb holepunch-dev`

Create a file system on the Holepunch device:

`mkfs.ext4 /dev/mapper/holepunch`

And finally mount the device!

```
mkdir -p /mnt/home
mount /dev/mapper/holepunch /mnt/home
```

You can now read and write encrypted file system content to `/mnt/home`!


## Benchamrking Utilities

This directory contains some simple wrappers for using Bonnie++ consistently.

```bash
./run_bench.sh

Usage: ./run_bench.sh -n [num] -d [dirs]

[num] : Number of files to create/delete
[dirs] : Number of subdirectories to split files across (default: 0)
```
