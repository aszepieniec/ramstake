#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <gmp.h>

#include "ramstake.h"
#include "csprng.h"

int main( int argc, char ** argv )
{
    unsigned long randomness;
    unsigned char * seed;
    mpz_t integer;
    csprng rng;
    unsigned char data[RAMSTAKE_SEED_LENGTH];
    int i;

    if( argc != 2 || strlen(argv[1]) % 2 != 0 )
    {
        printf("usage: ./test d13d13deadbeef\n");
        return 0;
    }

    csprng_init(&rng);
    seed = malloc(strlen(argv[1])/2);
    for( i = 0 ; i < strlen(argv[1]) ; ++i )
    {
        sscanf(argv[1] + 2*i, "%02x", seed + i);
    }
    csprng_seed(&rng, strlen(argv[1])/2, seed);
    free(seed);
   
    randomness = csprng_generate_ulong(&rng);

    printf("randomness: %lu\n", randomness);

    csprng_init(&rng);
    csprng_seed(&rng, sizeof(unsigned long), (unsigned char *)(&randomness));
    csprng_generate(&rng, RAMSTAKE_SEED_LENGTH, data);

    mpz_init(integer);

    ramstake_sample_small_sparse_integer(integer, data);

    mpz_out_str(stdout, 10, integer);
    printf("\n");

    mpz_clear(integer);

    return 0;
}

