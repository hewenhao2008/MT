INCLUDE=-I../../lua-5.1.5/src -I../libevhttp
LIB=-L../../lua-5.1.5/src -llua -ldl -L../libevhttp -levhttpclient
all:  
	$(CC) -fPIC -shared -o ehc.so ehc.c $(INCLUDE) $(LIB)  
	
clean:
	rm -f *.o *.so