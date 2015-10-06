TARGET := switch
KDIR   := /usr/src/linux-headers-$(shell uname -r)/
WDIR   := $(shell pwd)
obj-m  := $(TARGET).o
$(TARGET)-objs := main.o

default:
	@$(MAKE) -C $(KDIR) SUBDIRS=$(WDIR) modules
	@rm $(TARGET).o *.mod.c *.mod.o modules.order Module.symvers
reinstall:
	@if test -e /sys/module/$(TARGET); then rmmod $(TARGET); fi
	@$(MAKE) -C $(KDIR) SUBDIRS=$(WDIR) modules
	@rm $(TARGET).o *.mod.c *.mod.o modules.order Module.symvers
	@insmod $(WDIR)/$(TARGET).ko
install:
	@if ! test -e /sys/module/$(TARGET); then insmod $(WDIR)/$(TARGET).ko; fi
remove:
	@if test -e /sys/module/$(TARGET); then rmmod $(TARGET); fi
clean:
	@rm *.o *.mod.c modules.order Module.symvers
