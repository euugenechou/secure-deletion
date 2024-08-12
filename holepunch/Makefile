all: kmod userland

.PHONY: kmod
kmod:
	$(MAKE) -C ./kernel_module

.PHONY: userland
userland:
	$(MAKE) -C ./holepunch-userland notpm
