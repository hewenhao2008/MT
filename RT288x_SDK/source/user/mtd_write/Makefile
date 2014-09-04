EXEC = mtd_write
OBJS = mtd.o
CFLAGS += -I$(ROOTDIR)/$(LINUXDIR)
CFLAGS += -I$(ROOTDIR)/lib/libnvram

LDFLAGS += -lnvram

all: $(EXEC)

$(EXEC): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $(OBJS) $(LDLIBS)

romfs:
	$(ROMFSINST) /bin/$(EXEC)

clean:
	-rm -f $(EXEC) *.elf *.gdb *.o

