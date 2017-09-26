CC=gcc
CFLAGS=-I../../../../../KeccakCodePackage/bin/generic64/
OPTFLAGS=-O3
LFLAGS=-L../../../../../KeccakCodePackage/bin/generic64/ -lgmp -lkeccak -lcrypto
TEST_HEADERS = csprng.h  gf256x.h  ramstake.h  reedsolomon.h
TEST_SOURCE = csprng.c  gf256x.c  ramstake.c  reedsolomon.c  test.c 
KAT_HEADERS = csprng.h  gf256x.h  ramstake.h  reedsolomon.h  rng.h
KAT_SOURCES = csprng.c  gf256x.c  ramstake.c  reedsolomon.c  PQCgenKAT_kem.c  rng.c  kem.c

test: $(TEST_SOURCE) $(TEST_HEADERS)
	gcc -o $@ $(TEST_SOURCE) $(CFLAGS) $(LFLAGS)

kat: $(KAT_HEADERS) $(KAT_SOURCES)
	gcc -o PQCgenKAT_kem $(KAT_SOURCES) $(CFLAGS) $(LFLAGS) -std=c99 -DKAT

clean:
	rm *.o

