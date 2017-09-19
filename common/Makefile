CC=gcc
CFLAGS=-I../../KeccakCodePackage/bin/generic64/
LFLAGS=-L../../KeccakCodePackage/bin/generic64/ -lgmp -lkeccak
DEPS = *.h
OBJ = *.o 

test: $(OBJ)
	gcc -o $@ *.c $(CFLAGS) $(LFLAGS)

clean:
	rm *.o

