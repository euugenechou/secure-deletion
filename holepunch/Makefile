all: kmod userland

.PHONY: kmod
kmod:
	cd ./kernel_module && $(MAKE) modules_install

.PHONY: userland
userland:
	cd ./holepunch-userland && $(MAKE) symlink
