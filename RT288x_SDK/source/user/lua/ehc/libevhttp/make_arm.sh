#!/bin/sh 
arm-linux-gcc -I../libev-4.15/ -L../libev-4.15/.libs -fPIC -shared -O2 http_parser.c evhttpclient.cpp wrap.c -o libevhttpclient.so -lev -lstdc++
