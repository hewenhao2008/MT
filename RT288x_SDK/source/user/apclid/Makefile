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
LDFLAGS	+= -lnvram -liw -lm

# If you want to debug daemon, add following line
CFLAGS +=  -DDBG 

SRCS = $(wildcard *.c)
OBJS = $(patsubst %.c, %.o, $(SRCS))

all: apclid romfs

apclid: $(wildcard *.h) $(OBJS)
	$(CC) -o apclid $(OBJS) $(LDFLAGS)

clean:
	rm -f *~ *.o apclid *.d

# add by YYHuang@Ralink
romfs:
	install -d $(ROMFSDIR)/ugw/bin
	$(ROMFSINST) apclid /ugw/bin/apclid
	cd $(ROMFSDIR)/ugw/bin && ln -sf apclid wlconf; \
		ln -sf apclid press_any_key;

-include $(OBJS:%.o=%.d)
