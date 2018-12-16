.PHONY: modules modules_install clean

KVERSION := $(shell uname -r)
KERNEL_SRC := /lib/modules/$(KVERSION)/build

modules:
	$(MAKE) -C $(KERNEL_SRC) M=$(PWD) modules

modules_install: modules
	$(MAKE) -C $(KERNEL_SRC) M=$(PWD) modules_install

clean:
	$(MAKE) -C $(KERNEL_SRC) M=$(PWD) clean
	@rm -f Module.symvers *.o .*.cmd *.mod.c *.ko
