#ifndef BCH_H
#define BCH_H

#include "gf4096x.h"
#include "gf2x.h"

typedef struct
{
    unsigned int n, k, t, delta;
    gf2x generator;
} bch;

#define BCH_FIELD_GEN 0x002
bch bch_init( unsigned int n, unsigned int delta );
bch bch_init_kn( unsigned int k, unsigned int n );
int bch_destroy( bch codec );
int bch_encode( unsigned char * codeword, bch codec, unsigned char * message );
int bch_interrupted_euclid( gf4096x * sigma, gf4096x * omega, gf4096x syndrome, gf4096x gcap );
gf4096x bch_syndrome( bch codec, unsigned char * word );
int bch_decode_syndrome( unsigned char * errors, bch codec, gf4096x syndrome );
int bch_decode_error_free( unsigned char * message, bch codec, unsigned char * codeword );
int bch_decode( unsigned char * message, bch codec, unsigned char * codeword );

#endif

