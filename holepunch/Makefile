all: kmod userland

.PHONY: kmod
kmod:
	cd ./kernel_module && $(MAKE)

.PHONY: userland
userland:
	cd ./holepunch-userland && $(MAKE) notpm
