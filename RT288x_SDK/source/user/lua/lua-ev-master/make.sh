#!/bin/sh 
INCLUDE="-I/home/xt/vs/src/libev-4.15 -I/home/xt/vs/src/LuaJIT-2.0.3/src"
LIB="-L/home/xt/vs/lib"

gcc -O2 -fPIC -shared $INCLUDE $LIB lua_ev.c -o ev.so -lluajit -lev


