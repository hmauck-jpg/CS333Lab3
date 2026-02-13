CC = gcc
DEBUG = -g
DEFINES =
CFLAGS = $(DEBUG) -Wall -Wextra -Wshadow -Wunreachable-code
	-Wredundant-decls -Wmissing-declarations
	-Wold-style-definition -Wmissing-prototypes
	-Wdeclaration-after-statement -Wno-return-local-addr
	-Wunsafe-loop-optimizations -Wuninitialized -Werror
	-Wno-unused-parameter $(DEFINES)
PROG = desplodocus_mt
INCLUDES = desplodocus_mt.h

all: $(PROG)

$(PROG): $(PROG).o
	$(CC) $(CFLAGS) -o $@ $^ -lz

$(PROG).o: $(PROG).c $(INCLUDES)
	$(CC) $(CFLAGS) -c $<
 
clean cls:
	rm -f $(PROG) *.o *~ \#*

tar:
	tar cvfa tarasaur_${LOGNAME}.tar.gz desplodocus_mt.c [mM]akefile

git-checkin:
	if [ ! -d .git ] ; then git init; fi
	git add *.[ch] ?akefile
	git commit -m "automatic commit"






