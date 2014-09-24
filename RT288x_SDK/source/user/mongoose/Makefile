PLATFORM = RT2880

ifeq ($(PLATFORM),RT2880)
CROSS_COMPILE = mipsel-linux-
endif

CC = $(CROSS_COMPILE)gcc

ifndef CFLAGS
CFLAGS = -O2 -Wall -g
endif

CFLAGS	+= -I$(ROOTDIR)/lib/libnvram
CFLAGS	+= -I$(ROOTDIR)/user/wireless_tools

LDFLAGS += -L$(ROOTDIR)/user/wireless_tools
LDFLAGS	+= -lnvram -liw -lm -lpthread

# If you want to debug daemon, add following line
CFLAGS +=  -DDBG 

SRCS = $(wildcard *.c)
OBJS = $(patsubst %.c, %.o, $(SRCS))

all: httpd romfs

httpd: $(wildcard *.h) $(OBJS)
	$(CC) -o $@ $(OBJS) $(LDFLAGS)

clean:
	rm -f *~ *.o httpd *.d

# add by YYHuang@Ralink
romfs:
	install -d $(ROMFSDIR)/ugw/bin
	$(ROMFSINST) httpd /ugw/bin/httpd

-include $(OBJS:%.o=%.d)
