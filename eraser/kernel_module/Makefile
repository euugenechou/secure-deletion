LINUXROOT = ~/Desktop/linux

obj-m := dm-eraser.o

all:
	make -C $(LINUXROOT) M=$(PWD) modules

clean:
	make -C $(LINUXROOT) M=$(PWD) clean
