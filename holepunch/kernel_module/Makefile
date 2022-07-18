obj-m := dm-holepunch.o
dm-holepunch-y := dm-holepunch-main.o pprf-tree.o
# CFLAGS_dm-holepunch.o := -O0
# ccflags-y := -O0 -DDEBUG

all:
	make -C ~/Desktop/linux M=$(PWD) modules

debug: 
	make -C ~/Desktop/linux M=$(PWD) ccflags-y="-DDEBUG" modules

clean:
	make -C ~/Desktop/linux M=$(PWD) clean