CC=$(CROSS_COMPILE)gcc
AR=$(CROSS_COMPILE)ar
GCC=$(CROSS_COMPILE)g++
LD=$(CROSS_COMPILE)ld

INSTALLDIR?=$(ROMFSDIR)

#mipsel-ugw-linux-uclibc-

all:lua libev liblz4 luacjson luasocket luaev minizz basicc lz4d ehcc httpauthx

#all:ehcc
lua: 
	cd lua-5.1.5 && make linux CC=$(CC)
	
libev: 
	#cd libev-4.15 && ./configure --host=arm-linux && make  
	cd libev-4.15 && make
	#cd libev-4.15 && ./configure --host=mipsel-ugw-linux-uclibc && make
ehcc:
	cd ehc && make CC=$(CC) GCC=$(GCC)
basicc:
	cd basic && make CC=$(CC) 

liblz4:
	cd lz4-r118 && make CC=$(CC)

lz4d:liblz4
	cd lz4 && make CC=$(CC)	
	
luacjson:lua
	cd lua-cjson-master && make CC=$(CC)

luasocket:lua
	cd luasocket-2.0.2 && make CC=$(CC) 

luaev:lua libev
	cd lua-ev-master && make CC=$(CC)

minizz:
	cd miniz && make CC=$(CC)

httpauthx:
	cd httpauth && make CC=$(GCC)

romfs: install
	
install:  
	mkdir -p $(ROMFSDIR)/usr/lib/socket
	mkdir -p $(ROMFSDIR)/usr/lib/mime
	mkdir -p $(ROMFSDIR)/usr/sbin/scripts/auth 
	mkdir -p $(ROMFSDIR)/usr/sbin/scripts/socket/
	
	cp lua-5.1.5/src/lua $(ROMFSDIR)/usr/sbin/
	cp lua-5.1.5/src/luac $(ROMFSDIR)/usr/sbin/
	cp httpauth/httpauth $(ROMFSDIR)/usr/sbin/
	cp lua-5.1.5/src/liblua.so $(ROMFSDIR)/usr/lib/
	cp libev-4.15/.libs/libev.so.4.0.0 $(ROMFSDIR)/usr/lib 
	cd $(ROMFSDIR)/usr/lib && ln -sf libev.so.4.0.0 libev.so.4 && ln -sf libev.so.4.0.0 libev.so
	cp lua-cjson-master/*.so* $(ROMFSDIR)/usr/lib/
	cp basic/*.so* $(ROMFSDIR)/usr/lib/
	cp miniz/*.so* $(ROMFSDIR)/usr/lib/
	cp lz4/*.so* $(ROMFSDIR)/usr/lib/
	cp lz4-r118/*.so* $(ROMFSDIR)/usr/lib/
	cp ehc/libevhttp/*.so* $(ROMFSDIR)/usr/lib/
	cp ehc/ehc/*.so* $(ROMFSDIR)/usr/lib/
	cp ehc/script/*.lua $(ROMFSDIR)/usr/sbin/scripts/
	cp luasocket-2.0.2/src/socket.so.2.0.2 $(ROMFSDIR)/usr/lib/socket/core.so
	cp luasocket-2.0.2/src/mime.so.1.0.2 $(ROMFSDIR)/usr/lib/mime/core.so
	cp luasocket-2.0.2/src/ltn12.lua $(ROMFSDIR)/usr/sbin/scripts/
	cp luasocket-2.0.2/src/url.lua $(ROMFSDIR)/usr/sbin/scripts/socket/
	cp luasocket-2.0.2/src/mime.lua $(ROMFSDIR)/usr/sbin/scripts/
	cp luasocket-2.0.2/src/socket.lua $(ROMFSDIR)/usr/sbin/scripts/
	cp lua-ev-master/ev.so $(ROMFSDIR)/usr/lib/
	cp authd/script/*.lua $(ROMFSDIR)/usr/sbin/scripts/auth/
	cp authd/sh/* $(ROMFSDIR)/usr/sbin/
	chmod a+x $(ROMFSDIR)/usr/sbin/*
	cp script/*.lua $(ROMFSDIR)/usr/sbin/scripts/
	-$(STRIP) $(ROMFSDIR)/usr/sbin/*
	-$(STRIP) $(ROMFSDIR)/usr/lib/*.so*
	$(STRIP) $(ROMFSDIR)/usr/lib/socket/*.so*
	$(STRIP) $(ROMFSDIR)/usr/lib/mime/*.so*
	
clean:
	cd lua-5.1.5 && make clean   
	cd libev-4.15 && make clean
	cd lz4-r118 && make clean 
	cd lz4 && make clean 
	cd lua-cjson-master && make clean 
	cd luasocket-2.0.2 && make clean 
	cd lua-ev-master && make clean 
	cd ehc && make clean 
	cd basic && make clean 
	cd miniz && make clean 
	cd httpauth && make clean