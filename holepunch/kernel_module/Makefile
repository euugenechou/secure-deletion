obj-m := dm-holepunch.o
dm-holepunch-y := dm-holepunch-main.o pprf-tree.o


all:
	make -C ~/Desktop/linux M=$(PWD) modules ccflags-y="$(ccflags-y)"

debug: ccflags-y += -DHOLEPUNCH_DEBUG
debug: all

debug_semas: ccflags-y += -DHOLEPUNCH_SEMA -DHOLEPUNCH_DEBUG
debug_semas: all

clean:
	make -C ~/Desktop/linux M=$(PWD) clean