CC=$(CROSS_COMPILE)gcc
AR=$(CROSS_COMPILE)ar
GCC=$(CROSS_COMPILE)g++
LD=$(CROSS_COMPILE)ld

INSTALLDIR?=$(ROMFSDIR)

#mipsel-ugw-linux-uclibc-

all:lua libev liblz4 luacjson luasocket luaev minizz basicc lz4d ehcc

#all:ehcc
lua: 
	cd lua-5.1.5 && make linux CC=$(CC)
	
libev: 
	#cd libev-4.15 && ./configure --host=arm-linux && make  
	#cd libev-4.15 && make
	cd libev-4.15 && ./configure --host=mipsel-ugw-linux-uclibc && make
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

romfs: install
	
install:  
	mkdir -p $(INSTALLDIR)/usr/sbin/scripts/auth 
	mkdir -p $(INSTALLDIR)/usr/sbin/scripts/socket
	mkdir -p $(INSTALLDIR)/usr/lib/socket
	mkdir -p $(INSTALLDIR)/usr/lib/mime
	
	cp lua-5.1.5/src/lua $(INSTALLDIR)/usr/sbin/
	cp lua-5.1.5/src/liblua.so $(INSTALLDIR)/usr/lib/
	cp libev-4.15/.libs/libev.so.4.0.0 $(INSTALLDIR)/usr/lib
	cd $(INSTALLDIR)/usr/lib && ln -sf libev.so.4.0.0 libev.so.4
	cp lua-cjson-master/*.so* $(INSTALLDIR)/usr/lib/
	cp basic/*.so* $(INSTALLDIR)/usr/lib/
	cp miniz/*.so* $(INSTALLDIR)/usr/lib/
	cp lz4/*.so* $(INSTALLDIR)/usr/lib/
	cp lz4-r118/*.so* $(INSTALLDIR)/usr/lib/
	cp ehc/libevhttp/*.so* $(INSTALLDIR)/usr/lib/
	cp ehc/ehc/*.so* $(INSTALLDIR)/usr/lib/
	cp ehc/script/*.lua $(INSTALLDIR)/usr/sbin/scripts/
	cp luasocket-2.0.2/src/socket.so.2.0.2 $(INSTALLDIR)/usr/lib/socket/core.so
	cp luasocket-2.0.2/src/mime.so.1.0.2 $(INSTALLDIR)/usr/lib/mime/core.so
	cp luasocket-2.0.2/src/ltn12.lua $(INSTALLDIR)/usr/sbin/scripts/
	cp luasocket-2.0.2/src/mime.lua $(INSTALLDIR)/usr/sbin/scripts/
	cp luasocket-2.0.2/src/socket.lua $(INSTALLDIR)/usr/sbin/scripts/
	cp luasocket-2.0.2/src/url.lua $(INSTALLDIR)/usr/sbin/scripts/socket
	cp lua-ev-master/ev.so $(INSTALLDIR)/usr/lib/
	cp authd/script/*.lua $(INSTALLDIR)/usr/sbin/scripts/auth/
	cp authd/sh/* $(INSTALLDIR)/usr/sbin/
	cp script/*.lua $(INSTALLDIR)/usr/sbin/scripts/
	-$(STRIP) $(INSTALLDIR)/usr/lib/*.so*
	$(STRIP) $(INSTALLDIR)/usr/lib/socket/*.so*
	$(STRIP) $(INSTALLDIR)/usr/lib/mime/*.so*
	#for onescript in `find $(INSTALLDIR)/usr/sbin/scripts/ -name "*.lua"`; do luac -s -o $${onescript} $${onescript} ; done
	
clean:
	cd lua-5.1.5 && make clean   
	cd libev-4.15 && make distclean
	cd lz4-r118 && make clean 
	cd lz4 && make clean 
	cd lua-cjson-master && make clean 
	cd luasocket-2.0.2 && make clean 
	cd lua-ev-master && make clean 
	cd ehc && make clean 
	cd basic && make clean 
	cd miniz && make clean 