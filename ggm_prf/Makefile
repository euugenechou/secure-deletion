obj-m := pprf-tree.o

all:
	make -C ~/Desktop/linux M=$(PWD) modules

debug:
	make -C ~/Desktop/linux M=$(PWD) modules ccflags-y="-DDEBUG"

time:
	make -C ~/Desktop/linux M=$(PWD) modules ccflags-y="-DTIME"

clean:
	make -C ~/Desktop/linux M=$(PWD) clean