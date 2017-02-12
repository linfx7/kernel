CONFIG_MODULE_SIG=n

obj-m := sdig-kernel.o

sdig-kernel-objs := module_init.o netlink_kernel.o flow_cache.o

KERNELBUILD := /lib/modules/$(shell uname -r)/build

default:
	make -C $(KERNELBUILD) M=$(shell pwd) modules

clean:
	make -C $(KERNELBUILD) M=$(shell pwd) clean

install:
	sudo /sbin/insmod sdig-kernel.ko

remove:
	sudo /sbin/rmmod sdig-kernel

read:
	sudo cat /proc/kmsg

