ifeq ($(TEST),)
LINUXROOT := ~/linux
endif

obj-m := dm-eraser.o

all:
	make -C $(LINUXROOT) M=$(PWD) modules

clean:
	make -C $(LINUXROOT) M=$(PWD) clean
