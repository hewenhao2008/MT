EV_DEPEND_INCLUDE=-I../libev-4.15 -I../lua-5.1.5/src
EV_DEPEND_LIB=-L../libev-4.15/.libs -lev -L../lua-5.1.5/src -llua

all : ev.so 

ev.so:
	$(CC) -O2 -fPIC -shared $(EV_DEPEND_INCLUDE) $(EV_DEPEND_LIB) lua_ev.c -o ev.so

install: all
	echo "install"
	
clean:
	rm -f *.o ev.so 
	
