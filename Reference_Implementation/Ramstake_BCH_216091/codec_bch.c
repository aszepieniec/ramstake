#include "codec_bch.h"

/**
 * codec_bch_init
 * Create codec object for BCH repetition code.
 *
 */
void codec_bch_init( codec_bch * cd, int k, int n, int inner_n, int repetitions )
{
    cd->inner_codec = bch_init_kn(k, inner_n);

    cd->k = k;
    cd->repetitions = n / cd->inner_codec.n;
    if( repetitions > 0 && repetitions < cd->repetitions )
    {
        cd->repetitions = repetitions;
    }
    cd->n = 8*((cd->inner_codec.n+7)/8)*cd->repetitions;
}

/**
 * codec_bch_destroy
 * Destroy repetition BCH codec object.
 */
void codec_bch_destroy( codec_bch cd )
{
    bch_destroy(cd.inner_codec);
}

/**
 * codec_bch_encode
 * Encode a string of k bits into a repeated codeword of length n.
 * If k or n is not divisible by 8, the most significant bits of the
 * last byte is not used.
 */
void codec_bch_encode( unsigned char * dest, codec_bch cd, unsigned char * source )
{
    int i, j, n;
    bch_encode(dest, cd.inner_codec, source);
    n = (cd.inner_codec.n+7)/8;
    for( i = 1 ; i < cd.repetitions ; ++i )
    {
        for( j = 0 ; j < n ; ++j )
        {
            dest[i*n + j] = dest[j];
        }
    }
}

/**
 * codec_bch_decode
 * Decode a repeated BCH codeword of length n into a message of
 * length k bits. If either number is not divisible by 8, then the
 * most significant bits of the last byte are not used.
 */
int codec_bch_decode( unsigned char * dest, codec_bch cd, unsigned char * source, unsigned char * helper_data )
{
    int i, j;
    unsigned char hash[32];
    int equals;

    for( i = 0 ; i < cd.repetitions ; ++i )
    {
        bch_decode(dest, cd.inner_codec, source + i*(cd.inner_codec.n+7)/8);
        SHA3_256(hash, dest, 32);
        equals = 1;
        for( j = 0 ; j < 32 ; ++j )
        {
            equals &= (hash[j] == helper_data[j]);
        }
        if( equals == 1)
        {
            break;
        }
    }
    
    return equals;
}

