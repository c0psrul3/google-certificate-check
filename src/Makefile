CFLAGS = -Wall -Werror -I/usr/local/include -g
LDFLAGS = -L/usr/local/lib

VERSION = 0.1

all: google-certificate-check

google-certificate-check: google-certificate-check.o
	$(CC) $(CFLAGS) $(LDFLAGS) -o google-certificate-check google-certificate-check.o -lssl -lcrypto -lunbound

tarball:
	tar cvf google-certificate-check-$(VERSION).tar README Makefile google-certificate-check.c
	tardy -Prefix google-certificate-check-$(VERSION) google-certificate-check-$(VERSION).tar | gzip > google-certificate-check-$(VERSION).tgz
	rm google-certificate-check-$(VERSION).tar

*.o: Makefile
