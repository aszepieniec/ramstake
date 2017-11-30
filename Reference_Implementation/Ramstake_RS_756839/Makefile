CC=gcc
OPTFLAGS=-O3
CFLAGS=-I../../../KeccakCodePackage/bin/generic64/ # point this and the one below to wherever the keccak code package is located
LFLAGS=-L../../../KeccakCodePackage/bin/generic64/ -lgmp -lkeccak -lcrypto
TEST_HEADERS = csprng.h  gf256x.h  ramstake.h  reedsolomon.h 
TEST_SOURCE = csprng.c  gf256x.c  ramstake.c  reedsolomon.c  test.c codec_rs.c 
PERFORM_SOURCE = csprng.c  gf256x.c  ramstake.c  reedsolomon.c  perform.c codec_rs.c 
KAT_HEADERS = csprng.h  gf256x.h  ramstake.h  reedsolomon.h  rng.h 
KAT_SOURCES = csprng.c  gf256x.c  ramstake.c  reedsolomon.c  PQCgenKAT_kem.c  rng.c  kem.c codec_rs.c 

test: $(TEST_SOURCE) $(TEST_HEADERS)
	gcc -o $@ $(TEST_SOURCE) $(CFLAGS) $(LFLAGS)

perform: $(PERFORM_SOURCE) $(TEST_HEADERS)
	gcc -o $@ $(PERFORM_SOURCE) $(CFLAGS) $(LFLAGS) -Wall -lrt

kat: $(KAT_HEADERS) $(KAT_SOURCES)
	gcc -o PQCgenKAT_kem $(KAT_SOURCES) $(CFLAGS) $(LFLAGS) -std=c99 -DKAT

api: ramstake.h genapi.c
	gcc -o genapi genapi.c
	./genapi > api.h
	rm -f genapi

clean:
	rm -f *.o
	rm -f test
	rm -f perform
	rm -f kat
	rm -f genapi

