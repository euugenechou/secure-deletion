obj-m := dm-holepunch.o
dm-holepunch-y := dm-holepunch-main.o pprf-tree.o

SRC := $(wildcard *.c)
KMOD_FILE := dm-holepunch.ko
KMOD := dm_holepunch

ifeq ($(TEST),)
KDIR := /lib/modules/`uname -r`/build
endif

BATCH=1
ifeq ($(BATCH),1)
ccflags-y += -DHOLEPUNCH_BATCHING
endif

JNL=1
ifeq ($(JNL), 1)
ccflags-y += -DHOLEPUNCH_JOURNAL
endif

PPRF_TEST=0
ifeq ($(PPRF_TEST),1)
ccflags-y += -DPPRF_TEST
endif

PPRF_TIME=0
ifeq ($(PPRF_TIME),1)
ccflags-y += -DPPRF_TIME
endif

.PHONY: all
all: $(KMOD_FILE)

$(KMOD_FILE): $(SRC)
	$(MAKE) -C $(KDIR) M=$$PWD modules ccflags-y="$(ccflags-y)"

.PHONY: modules_install
modules_install: $(KMOD_FILE)
	$(MAKE) -C $(KDIR) M=$$PWD modules_install

.PHONY: reload
reload: $(KMOD_FILE)
	if lsmod | grep $(KMOD) > /dev/null; then rmmod $(KMOD); fi
	insmod $(KMOD_FILE)

.PHONY: debug
debug: ccflags-y += -DHOLEPUNCH_DEBUG
debug: all

.PHONY: debug_semas
debug_semas: ccflags-y += -DHOLEPUNCH_SEMA -DHOLEPUNCH_DEBUG
debug_semas: all

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
