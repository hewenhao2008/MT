LUA_INCLUDE=-I../lua-5.1.5/src/
LUA_LIB=-L../lua-5.1.5/src/ -llua
JSON_SOURCE=lua_cjson.c strbuf.c
JSON_SOURCE+=fpconv.c
#SOURCE+=g_fmt.c dtoa.c 

all : cjson.so 

cjson.so:
	$(CC) -O2 -fPIC -shared $(LUA_INCLUDE) $(JSON_SOURCE) -o cjson.so $(LUA_LIB)

install: all
	echo "install"
	
clean:
	rm -f *.o *.so 
	