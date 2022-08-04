obj-m := dm-holepunch.o
dm-holepunch-y := dm-holepunch-main.o pprf-tree.o

BATCH=0
ifeq ($(BATCH),1)
ccflags-y += -DHOLEPUNCH_BATCHING
endif

PPRF_TEST=0
ifeq ($(PPRF_TEST),1)
ccflags-y += -DHOLEPUNCH_PPRF_TEST
endif

PPRF_TIME=0
ifeq ($(PPRF_TIME),1)
ccflags-y += -DHOLEPUNCH_PPRF_TIME
endif



all:
	make -C ~/Desktop/linux M=$(PWD) modules ccflags-y="$(ccflags-y)" V=1

debug: ccflags-y += -DHOLEPUNCH_DEBUG
debug: all

debug_semas: ccflags-y += -DHOLEPUNCH_SEMA -DHOLEPUNCH_DEBUG
debug_semas: all

clean:
	make -C ~/Desktop/linux M=$(PWD) clean