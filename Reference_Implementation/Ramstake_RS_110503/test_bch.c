#include "bch.h"
#include "csprng.h"
#include <stdio.h>
#include <stdlib.h>

int test_generator( unsigned char * random )
{
    bch codec;
    csprng rng;
    int n, delta;

    csprng_init(&rng);
    csprng_seed(&rng, 8, random);

    delta = 10 + (csprng_generate_ulong(&rng) % 100);
    n = 12*delta + 10 + (csprng_generate_ulong(&rng) % 100);

    printf("testing bch codec generation with n = %i and delta = %i ... ", n, delta);

    codec = bch_init(n, delta);

    if( codec.k > 0 )
    {
        printf("success, with generator = "); gf2x_print(codec.generator); printf(" and k = %i\n", codec.k);
    }
    else
    {
        printf("failure: k < 0\n");
    }

    bch_destroy(codec);

    return 1;

}

int test_encode( unsigned char * random )
{
    bch codec;

    int n, delta, k;
    unsigned char * msg;
    unsigned char * cdwd;
    unsigned char * msg_;
    int equals;
    int i;
    csprng rng;

    csprng_init(&rng);
    csprng_seed(&rng, 8, random);

    delta = 10 + (csprng_generate_ulong(&rng) % 100);
    n = 12*delta + 10 + (csprng_generate_ulong(&rng) % 100);


    codec = bch_init(n, delta);
    k = codec.k;
    printf("testing bch encoding with n = %i and delta = %i and consequently k = %i ... ", n, delta, k);

    msg = malloc((k+1+7)/8);
    for( i = 0 ; i < (k+1+7)/8 ; ++i )
    {
        msg[i] = 0;
    }
    for( i = 0 ; i < k ; ++i )
    {
        msg[i/8] ^= (csprng_generate_ulong(&rng)%2) << (i % 8);
    }

    cdwd = malloc((n+1+8)/8);
    bch_encode(cdwd, codec, msg);

    printf("message ");
    for( i = 0 ; i < k ; ++i )
    {
        printf("%i", (msg[i/8] & (1 << (i%8))) != 0);
    }
    printf(" encoded as ");
    for( i = 0 ; i < n ; ++i )
    {
        printf("%i", (cdwd[i/8] & (1 << (i % 8))) != 0);
    }

    msg_ = malloc((k+1+7)/8);
    printf(" decoded as ");
    equals = bch_decode_error_free(msg_, codec, cdwd);
    for( i = 0 ; i < (k+1+7)/8 ; ++i )
    {
        equals &= (msg[i] == msg_[i]);
    }
    for( i = 0 ; i < k ; ++i )
    {
        printf("%i", (msg_[i/8] & (1 << (i%8))) != 0);
    }
    if( equals == 1 )
    {
        printf(" success! \\o/\n");
    }
    else
    {
        printf(" failure! <o>\n");
    }


    free(msg);
    free(msg_);
    free(cdwd);
    bch_destroy(codec);

    return equals;
}

int test_correction( unsigned char * random )
{
    bch codec;

    int n, delta, k, num_errors, pos;
    unsigned char * msg;
    unsigned char * cdwd;
    unsigned char * msg_;
    int equals;
    int i;
    csprng rng;

    csprng_init(&rng);
    csprng_seed(&rng, 8, random);

    delta = 10 + (csprng_generate_ulong(&rng) % 20);
    n = 12*delta + 10 + (csprng_generate_ulong(&rng) % 50);
    num_errors = (csprng_generate_ulong(&rng) % (1+(delta-1)/2));


    codec = bch_init(n, delta);
    k = codec.k;
    printf("testing bch error correction with n = %i and delta = %i and consequently k = %i and with (but not consequently) number of errors %i ... \n", n, delta, k, num_errors);

    msg = malloc((k+1+7)/8);
    for( i = 0 ; i < (k+1+7)/8 ; ++i )
    {
        msg[i] = 0;
    }
    for( i = 0 ; i < k ; ++i )
    {
        msg[i/8] ^= (csprng_generate_ulong(&rng)%2) << (i % 8);
    }

    cdwd = malloc((n+1+8)/8);
    bch_encode(cdwd, codec, msg);

    printf("message ");
    for( i = 0 ; i < k ; ++i )
    {
        printf("%i", (msg[i/8] & (1 << (i%8))) != 0);
    }
    printf(" encoded as ");
    for( i = 0 ; i < n ; ++i )
    {
        printf("%i", (cdwd[i/8] & (1 << (i % 8))) != 0);
    }

    printf(" adding errors in positions ");
    for( i = 0 ; i < num_errors ; ++i )
    {
        pos = csprng_generate_ulong(&rng) % n;
        printf(" %i ", pos);
        cdwd[pos/8] ^= 1 << (pos % 8);
    }

    msg_ = malloc((k+1+7)/8);
    equals = bch_decode(msg_, codec, cdwd);
    printf("decoded as ");
    for( i = 0 ; i < (k+1+7)/8-1 ; ++i )
    {
        equals &= (msg[i] == msg_[i]);
    }
    equals &= (((((msg[k/8] ^ msg_[k/8]) << (8 - (k%8)))) & 0xff) == 0);
    for( i = 0 ; i < k ; ++i )
    {
        printf("%i", (msg_[i/8] & (1 << (i%8))) != 0);
    }
    if( equals == 1 )
    {
        printf(" success! \\o/\n");
    }
    else
    {
        printf(" failure! <o>\n");
    }


    free(msg);
    free(msg_);
    free(cdwd);
    bch_destroy(codec);

    return equals;
}

int test_kn( unsigned char * random )
{
    bch codec;

    int n, delta, k, num_errors, pos;
    unsigned char * msg;
    unsigned char * cdwd;
    unsigned char * msg_;
    int equals;
    int i;
    csprng rng;

    csprng_init(&rng);
    csprng_seed(&rng, 8, random);

    k = 10 + (csprng_generate_ulong(&rng) % 50);
    n = k + 10 + (csprng_generate_ulong(&rng) % 1000);
    codec = bch_init_kn(k, n);
    delta = codec.delta;
    num_errors = (csprng_generate_ulong(&rng) % (1+(delta-1)/2));
    k = codec.k;
    printf("testing bch codec (k,n)-generation with n = %i and k = %i and delta = %i and with (but not consequently) number of errors %i ... \n", n, k, delta, num_errors);

    msg = malloc((k+1+7)/8);
    for( i = 0 ; i < (k+1+7)/8 ; ++i )
    {
        msg[i] = 0;
    }
    for( i = 0 ; i < k ; ++i )
    {
        msg[i/8] ^= (csprng_generate_ulong(&rng)%2) << (i % 8);
    }

    cdwd = malloc((n+1+8)/8);
    bch_encode(cdwd, codec, msg);

    printf("message ");
    for( i = 0 ; i < k ; ++i )
    {
        printf("%i", (msg[i/8] & (1 << (i%8))) != 0);
    }
    printf(" encoded as ");
    for( i = 0 ; i < n ; ++i )
    {
        printf("%i", (cdwd[i/8] & (1 << (i % 8))) != 0);
    }

    printf(" adding errors in positions ");
    for( i = 0 ; i < num_errors ; ++i )
    {
        pos = csprng_generate_ulong(&rng) % n;
        printf(" %i ", pos);
        cdwd[pos/8] ^= 1 << (pos % 8);
    }

    msg_ = malloc((k+1+7)/8);
    equals = bch_decode(msg_, codec, cdwd);
    printf("decoded as ");
    for( i = 0 ; i < (k+1+7)/8-1 ; ++i )
    {
        equals &= (msg[i] == msg_[i]);
    }
    equals &= (((((msg[k/8] ^ msg_[k/8]) << (8 - (k%8)))) & 0xff) == 0);
    for( i = 0 ; i < k ; ++i )
    {
        printf("%i", (msg_[i/8] & (1 << (i%8))) != 0);
    }
    if( equals == 1 )
    {
        printf(" success! \\o/\n");
    }
    else
    {
        printf(" failure! <o>\n");
    }


    free(msg);
    free(msg_);
    free(cdwd);
    bch_destroy(codec);

    return equals;
}

int main( int argc, char ** argv )
{

    unsigned int random;
    int i;
    int success;
    csprng rng;
    unsigned char rr[4];
    unsigned char seed[8];

    random = 0xdeadbeef;
    random = 0xefbeadde;

    csprng_init(&rng);
    csprng_seed(&rng, 4, (unsigned char*)(&random));
    
    csprng_generate(&rng, 4, rr);
    printf("Running series of tests with randomness %02x%02x%02x%02x ...\n", rr[0], rr[1], rr[2], rr[3]);

    success = 1;
    for( i = 0 ; i < 10 && success == 1 ; ++i )
    {
        csprng_generate(&rng, 8, seed);
        success &= test_generator(seed);
    }
    for( i = 0 ; i < 10 && success == 1 ; ++i )
    {
        csprng_generate(&rng, 8, seed);
        success &= test_encode(seed);
    }
    for( i = 0 ; i < 10 && success == 1 ; ++i )
    {
        csprng_generate(&rng, 8, seed);
        success &= test_correction(seed);
    }
    for( i = 0 ; i < 10 && success == 1 ; ++i )
    {
        csprng_generate(&rng, 8, seed);
        success &= test_kn(seed);
    }

    if( success == 1 )
    {
        printf("success.\n");
        return 1;
    }
    else
    {
        printf("failure.\n");
        return 0;
    }
}

