
all: libipsecutil

libipsecutil: libipsecutil.c
	gcc -m64 -I../usr/src/lib/libipsecutil/common \
	    -o $@ $< \
	    -L../proto/root_i386-nd/usr/lib/amd64/ \
	    -R../proto/root_i386-nd/usr/lib/amd64/ \
	    -lipsecutil -lcrypto

clean:
	rm -f libipsecutil

