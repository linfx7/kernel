CONFIG_MODULE_SIG=n

obj-m := netlink-test.o

netlink-test-objs := module_init.o netlink_kernel.o

KERNELBUILD := /lib/modules/$(shell uname -r)/build

default:
	make -C $(KERNELBUILD) M=$(shell pwd) modules

clean:
	make -C $(KERNELBUILD) M=$(shell pwd) clean

install:
	sudo /sbin/insmod netlink-test.ko

remove:
	sudo /sbin/rmmod netlink-test

read:
	sudo cat /proc/kmsg
