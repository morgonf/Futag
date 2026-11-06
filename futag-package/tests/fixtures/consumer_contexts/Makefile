CC ?= cc
all: liblibrary.a
liblibrary.a: library.o
	ar rcs $@ $^
library.o: library.c library.h
	$(CC) $(CFLAGS) -c library.c -o library.o
clean:
	rm -f *.o *.a
