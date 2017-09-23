CC=gcc
CFLAGS=-I../../KeccakCodePackage/bin/generic64/
OPTFLAGS=-O3
LFLAGS=-L../../KeccakCodePackage/bin/generic64/ -lgmp -lkeccak
DEPS = *.h *.c

test: $(DEPS)
	gcc -o $@ *.c $(CFLAGS) $(LFLAGS)

opt: $(DEPS)
	gcc -o test *.c $(CFLAGS) $(LFLAGS) $(OPTFLAGS)

clean:
	rm *.o

