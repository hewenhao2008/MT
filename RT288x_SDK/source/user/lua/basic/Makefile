INCLUDE=-I../lua-5.1.5/src
LIB=-L../lua-5.1.5/src -llua -ldl
all:
	$(CC) -fPIC -shared -o basic.so basic.c $(INCLUDE) $(LIB)  
clean:
	rm -f *.o *.so 