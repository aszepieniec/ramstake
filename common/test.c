#include <stdio.h>
#include <stdlib.h>
#include <gmp.h>

#include "ramstake.h"
#include "csprng.h"

int main( int argc, char ** argv )
{
    unsigned long randomness;
    mpz_t integer;
    csprng rng;
    unsigned char data[RAMSTAKE_SEED_LENGTH];
    int i;
   
    randomness = rand();

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

