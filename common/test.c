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
    int equals;

    ramstake_public_key pk;
    ramstake_secret_key sk;
    ramstake_ciphertext c;
    unsigned char pk_bytes[RAMSTAKE_PUBLIC_KEY_LENGTH];
    unsigned char sk_bytes[RAMSTAKE_SECRET_KEY_LENGTH];
    unsigned char c_bytes[RAMSTAKE_CIPHERTEXT_LENGTH];
    unsigned char key1[RAMSTAKE_KEY_LENGTH];
    unsigned char key2[RAMSTAKE_KEY_LENGTH];

    if( argc != 2 || strlen(argv[1]) % 2 != 0 )
    {
        printf("usage: ./test d13d13deadbeef\n");
        return 0;
    }

    csprng_init(&rng);
    seed = malloc(strlen(argv[1])/2);
    for( i = 0 ; i < strlen(argv[1])/2 ; ++i )
    {
        sscanf(argv[1] + 2*i, "%2hhx", &seed[i]);
    }
    csprng_seed(&rng, strlen(argv[1])/2, seed);
    free(seed);
   
    randomness = csprng_generate_ulong(&rng);

    printf("randomness: %lu\n", randomness);

    ramstake_public_key_init(&pk);
    ramstake_secret_key_init(&sk);
    ramstake_ciphertext_init(&c);

    seed = malloc(RAMSTAKE_SEED_LENGTH);
    csprng_generate(&rng, RAMSTAKE_SEED_LENGTH, seed);
    ramstake_keygen(&sk, &pk, seed, 1);
    free(seed);
    ramstake_export_public_key(pk_bytes, pk);
    ramstake_export_secret_key(sk_bytes, sk);

    ramstake_import_public_key(&pk, pk_bytes);
    seed = malloc(RAMSTAKE_SEED_LENGTH);
    csprng_generate(&rng, RAMSTAKE_SEED_LENGTH, seed);
    ramstake_encaps(&c, key1, pk, seed, 1);
    free(seed);
    ramstake_export_ciphertext(c_bytes, c);

    ramstake_import_ciphertext(&c, c_bytes);
    //ramstake_import_secret_key(&sk, sk_bytes);
    ramstake_decaps(key2, c, sk, 1);

    equals = 1;
    for( i = 0 ; i < RAMSTAKE_KEY_LENGTH ; ++i )
    {
        equals &= (key1[i] == key2[i]);
    }
    if( equals == 1 )
    {
        printf("success! k1 == k2 \\o/\n");
    }

    ramstake_public_key_destroy(pk);
    ramstake_secret_key_destroy(sk);
    ramstake_ciphertext_destroy(c);

    return 0;
}

