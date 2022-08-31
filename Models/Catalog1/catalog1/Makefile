
CC := gcc
CFLAGS := -std=c99
 
# The full path to the directory containing the makefile:
mkfile_dir := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))
 
# Build everything:
all: libcatalog1

clean:
	rm -rf ./bin
 
libcatalog1: bin/libcatalog1.so
 
bin/libcatalog1.so: catalog1.c | bin
	$(CC) -shared -Wl,--soname,libcatalog1.so \
                -o $@ -fPIC $< $(CFLAGS) -O3
 
bin:
	mkdir -p ./bin
 
.PHONY: libcatalog1 clean all