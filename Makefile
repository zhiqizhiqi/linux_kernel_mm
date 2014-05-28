obj-m:=zzq_vm.o
KDIR:=/lib/modules/$(shell uname -r)/build

PWD:=$(shell pwd)

default:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean: 
	rm -rf *.o *.ko *.mod.o
