CFLAGS_EXTRA += -DMONGOOSE_NO_THREADS -DNS_DISABLE_THREADS -DMONGOOSE_NO_CGI -DMONGOOSE_NO_DAV -DMONGOOSE_NO_WEBSOCKET\
-DMONGOOSE_USE_LUA -DMONGOOSE_USE_LUA_SQLITE3 -DNS_DISABLE_THREADS -DMONGOOSE_NO_AUTH
CFLAGS = -W -Wall -I.. -pipe $(CFLAGS_EXTRA)
RM = rm -rf
TARGET = httpauth
#CC=mipsel-linux-uclibc-g++ 

all: httpauth

httpauth: server.c mongoose.c cJSON.c
	$(CC) server.c mongoose.c cJSON.c -o $(TARGET)  $(CFLAGS)

clean:
	-@$(RM) *.o $(TARGET)

install: all
	install -D httpauth $(INSTALLDIR)/usr/sbin/httpauth
	$(STRIP) $(INSTALLDIR)/usr/sbin/httpauth