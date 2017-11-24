#include "codec_rs.h"

/**
 * codec_rs_init
 * Create codec object for RS repetition code.
 */
void codec_rs_init( codec_rs * cd, int k, int n, int inner_n, int repetitions )
{
    cd->k = k;
    cd->repetitions = n / 2128;
    if( repetitions > 0 && repetitions < cd->repetitions )
    {
        cd->repetitions = repetitions;
    }
    cd->n = 2128*repetitions;
}

/**
 * codec_rs_destroy
 * Destroy repetition RS codec object.
 */
void codec_rs_destroy( codec_rs cd )
{
}

/**
 * codec_rs_encode
 * Encode a string of k bits into a repeated codeword of length n.
 * If k or n is not divisible by 8, the most significant bits of the
 * last byte is not used.
 */
void codec_rs_encode( unsigned char * dest, codec_rs cd, unsigned char * source )
{
    rs_encode_multiple(dest, source, cd.repetitions);
}

/**
 * codec_rs_decode
 * Decode a repeated RS codeword of length n into a message of
 * length k bits. If either number is not divisible by 8, then the
 * most significant bits of the last byte are not used.
 */
int codec_rs_decode( unsigned char * dest, codec_rs cd, unsigned char * source, unsigned char * helper_data )
{
    int num_errors;
    num_errors = rs_decode_multiple(dest, source, cd.repetitions);
    return num_errors != -1;
}

