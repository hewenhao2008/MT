INCLUDE=-I../lua-5.1.5/src -I../lz4-r118/
LIB=-L../lua-5.1.5/src -llua -L../lz4-r118/ -llz4 -ldl 
all:
	$(CC) -fPIC -shared -o lz4.so *.c $(INCLUDE) $(LIB) 
	
clean:
	rm -f *.o *.so