obj-m := pprf-tree.o

all:
	make -C ~/Desktop/linux M=$(PWD) modules ccflags-y="-DDEBUG"

clean:
	make -C ~/Desktop/linux M=$(PWD) clean