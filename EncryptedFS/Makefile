COMPILER = gcc
FILESYSTEM_FILES = lsysfs.c encryption.c

CFLAGS = -I./include -I/usr/include/openssl
# OpenSSL library flags
LDFLAGS = -lssl -lcrypto

build: $(FILESYSTEM_FILES)
	$(COMPILER) -g -fstack-protector-all $(CFLAGS) $(FILESYSTEM_FILES) -o lsysfs `pkg-config fuse --cflags --libs` $(LDFLAGS)
	echo 'To Mount: ./lsysfs -f [mount point] [is_correct_key]'

clean:
	rm -f lsysfs
