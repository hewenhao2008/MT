TOPDIR=../
include $(TOPDIR)Rules.mk

#-include $(TOPDIR)/.config
#-include $(ROOTDIR)/$(LINUXDIR)/.config

#CFLAGS+=$(SSP_ALL_CFLAGS)
CFLAGS +=-DUSE_HOSTCC -fPIC
CFLAGS +=-I$(TOPDIR)libugw/include

#GPIO
CFLAGS +=-I$(ROOTDIR)/$(LINUXDIR)/drivers/char

LIBUGW=libugw.a
LIBUGW_SHARED=libugw.so

SRCS = $(wildcard *.c)
OBJS = $(patsubst %.c, %.o, $(SRCS))

HEADERS := ugw.h \
	$(ROOTDIR)/$(LINUXDIR)/include/linux/autoconf.h \
	$(ROOTDIR)/$(LINUXDIR)/drivers/char/ralink_gpio.h

all: $(LIBUGW)


$(OBJS): %.o : %.c
	$(CC) $(CFLAGS) -c $< -o $@
	$(STRIPTOOL) -x -R .note -R .comment $*.o

shared:
	$(LD) $(LDFLAGS) -soname=$(LIBUGW_SHARED) \
		-o $(LIBUGW_SHARED) --whole-archive $(LIBUGW) \
		--no-whole-archive \
		--shared \
		-L$(TOPDIR)lib -lc $(LDADD_LIBFLOAT) $(LIBGCC);
		#$(TOPDIR)libc/misc/internals/interp.o \
	$(INSTALL) -d $(TOPDIR)lib
	$(RM) $(TOPDIR)lib/$(LIBUGW_SHARED)
	$(INSTALL) -m 644 $(LIBUGW_SHARED) $(TOPDIR)lib

$(LIBUGW): $(OBJS)
	$(AR) $(ARFLAGS) $(LIBUGW) $(OBJS)
	$(INSTALL) -d $(TOPDIR)lib
	$(RM) $(TOPDIR)lib/$(LIBUGW)
	$(INSTALL) -m 644 $(LIBUGW) $(TOPDIR)lib

$(OBJS): $(HEADERS) Makefile

clean:
	$(RM) *.[oa] $(LIBUGW_SHARED)*

