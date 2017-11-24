#ifndef CODEC_BCH
#define CODEC_BCH

#include "bch.h"

typedef struct
{
    int n;
    int k;
    int delta;
    int repetitions;
    bch inner_codec;
} codec_bch;


void codec_bch_init( codec_bch * cd, int k, int n, int inner_n, int repetitions );
void codec_bch_destroy( codec_bch cd );
void codec_bch_encode( unsigned char * dest, codec_bch cd, unsigned char * source );
int codec_bch_decode( unsigned char * dest, codec_bch cd, unsigned char * source, unsigned char * helper_data );

#endif

