CC=gcc
CFLAGS=-Wall

all: example

include syscall-reporter.mk

example: example.o syscall-reporter.o

.PHONY: clean
clean:
	rm -f example example.o

syscall-reporter:
	echo "static const char *syscall_names[] = {" > syscall-names.h ;\
        echo "#include <syscall.h>" | cpp -dM | grep '^#define __NR_' | \
                LC_ALL=C sed -r -n -e 's/^\#define[ \t]+__NR_([a-z0-9_]+)[ \t]+([0-9]+)(.*)/ [\2] = "\1",/p' >> syscall-names.h;\
        echo "};" >> syscall-names.h;\
	gcc -Wall   -c -o syscall-reporter.o syscall-reporter.c

with:
	gcc   example.o syscall-reporter.o   -o example

