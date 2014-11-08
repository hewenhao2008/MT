PLATFORM = RT2880

ifeq ($(PLATFORM),RT2880)
CROSS_COMPILE = mipsel-linux-
endif

CC = $(CROSS_COMPILE)gcc

ifndef CFLAGS
CFLAGS = -O2 -Wall -g
endif

CFLAGS	+= -I$(ROOTDIR)/lib/libnvram
CFLAGS	+= -I$(ROOTDIR)/lib/libugw

LDFLAGS	+= -lnvram -lm -lugw

# If you want to debug daemon, add following line
CFLAGS +=  -DDBG 

SRCS = $(wildcard *.c)
OBJS = $(patsubst %.c, %.o, $(SRCS))

all: httpd romfs

httpd: $(wildcard *.h) $(OBJS)
	$(CC) -o httpd $(OBJS) $(LDFLAGS)

clean:
	rm -f *~ *.o httpd *.d

romfs:
	install -d $(ROMFSDIR)/ugw/bin
	$(ROMFSINST) httpd /ugw/bin/httpd
	mkdir -p $(ROMFSDIR)/ugw/webui
	mkdir -p $(ROMFSDIR)/usr/share/resource
	cp -a webui 	$(ROMFSDIR)/ugw/
	cp -a resource 	$(ROMFSDIR)/usr/share/
	$(ROMFSINST) -s /usr/share/resource /ugw/webui/resource

-include $(OBJS:%.o=%.d)
