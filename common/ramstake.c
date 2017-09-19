#include <stdio.h>
#include <stdlib.h>
#include <libkeccak.a.headers/SimpleFIPS202.h>
#include "ramstake.h"
#include "csprng.h"
#include "reedsolomon.h"

/**
 * ramstake_keygen
 * Generate a key pair from the given seed.
 */
int ramstake_keygen( ramstake_secret_key * sk, ramstake_public_key * pk, unsigned char * random_seed, int kat )
{
    csprng rng, rng2;
    int i;
    unsigned char * data;
    mpz_t g, p;

    mpz_init(p);
    mpz_init(g);

    csprng_init(&rng);
    csprng_seed(&rng, RAMSTAKE_SEED_LENGTH, random_seed);

    if( kat == 1 )
    {
        printf("# ramstake_keygen\n");
        printf("seed:  ");
        for( i = 0 ; i < RAMSTAKE_SEED_LENGTH ; ++i )
        {
            printf("%02x", random_seed[i]);
        }
        printf("\n");
    }

    /* record random seed into secret key */
    /* (In theory, the secret key need not contain any other data
     * because it can be generated from this seed. Nevertheless, we
     * include it directly for faster computations.) */
    for( i = 0 ; i < RAMSTAKE_SEED_LENGTH ; ++i )
    {
        sk->seed[i] = random_seed[i];
    }

    /* init modulus */
    ramstake_modulus_init(p);

    /* generate randomness for g */
    csprng_generate(&rng, RAMSTAKE_SEED_LENGTH, pk->seed);

    /* generate g from seed */
    csprng_init(&rng2);
    csprng_seed(&rng2, RAMSTAKE_SEED_LENGTH, pk->seed);
    data = malloc(RAMSTAKE_MODULUS_BITSIZE/8);
    csprng_generate(&rng2, RAMSTAKE_MODULUS_BITSIZE/8, data);
    mpz_import(g, RAMSTAKE_MODULUS_BITSIZE/8, 1, sizeof(unsigned char), 1, 0, data);
    free(data);

    if( kat == 1 )
    {
        printf("seed for generating g: ");
        for( i = 0 ; i < RAMSTAKE_SEED_LENGTH ; ++i )
        {
            printf("%02x", pk->seed[i]);
        }
        printf("\n");
        printf("g: ");
        mpz_out_str(stdout, 10, g);
        printf("\n");
    }

    /* sample sk integers a and b */
    data = malloc(RAMSTAKE_SEED_LENGTH);
    csprng_generate(&rng, RAMSTAKE_SEED_LENGTH, data);
    ramstake_sample_small_sparse_integer(sk->a, data);
    free(data);

    data = malloc(RAMSTAKE_SEED_LENGTH);
    csprng_generate(&rng, RAMSTAKE_SEED_LENGTH, data);
    ramstake_sample_small_sparse_integer(sk->b, data);
    free(data);

    /* compute pk integer c = ag + b mod p */
    mpz_mul(pk->c, g, sk->a);
    mpz_add(pk->c, pk->c, sk->b);
    mpz_mod(pk->c, pk->c, p);

    /* free remaining unfreed variables */
    mpz_clear(p);
    mpz_clear(g);

    return 0;
}

/**
 * ramstake_encaps
 * Encapsulate a symmetric key under a ramstake public key.
 */
int ramstake_encaps( ramstake_ciphertext * c, unsigned char * key, ramstake_public_key pk, unsigned char * randomness, int kat )
{
    csprng rng;
    csprng rng2;
    mpz_t a, b;
    mpz_t p;
    mpz_t g;
    mpz_t s;
    int i;
    unsigned char * data;

    mpz_init(p);
    ramstake_modulus_init(p);

    csprng_init(&rng);
    csprng_seed(&rng, RAMSTAKE_SEED_LENGTH, randomness);

    /* sample integers a, b */
    mpz_init(a);
    data = malloc(RAMSTAKE_SEED_LENGTH);
    csprng_generate(&rng, RAMSTAKE_SEED_LENGTH, data);
    ramstake_sample_small_sparse_integer(a, data);
    free(data);

    mpz_init(b);
    data = malloc(RAMSTAKE_SEED_LENGTH);
    csprng_generate(&rng, RAMSTAKE_SEED_LENGTH, data);
    ramstake_sample_small_sparse_integer(b, data);
    free(data);

    /* re-generate g from pk seed */
    csprng_init(&rng2);
    csprng_seed(&rng2, RAMSTAKE_SEED_LENGTH, pk.seed);
    data = malloc(RAMSTAKE_MODULUS_BITSIZE/8);
    csprng_generate(&rng2, RAMSTAKE_MODULUS_BITSIZE/8, data);
    mpz_init(g);
    mpz_import(g, RAMSTAKE_MODULUS_BITSIZE/8, 1, sizeof(unsigned char), 1, 0, data);
    free(data);

    /* compute d = ag + b mod p */
    mpz_mul(c->d, a, g);
    mpz_add(c->d, c->d, b);
    mpz_mod(c->d, c->d, p);

    /* compute local data stream integer s = ca mod p */
    mpz_init(s);
    mpz_mul(s, pk.c, a);
    mpz_mod(s, s, p);

    /* draw pseudorandom stream from integer */
    data = malloc(RAMSTAKE_MODULUS_BITSIZE/8);
    mpz_export(data, NULL, 1, 1, 1, 0, s);
    /* we only care about the first (most significant) 1020 bytes. */
    for( i = 0 ; i < RAMSTAKE_SEEDENC_LENGTH ; ++i )
    {
        c->e[i] = data[RAMSTAKE_MODULUS_BITSIZE/8 - RAMSTAKE_SEEDENC_LENGTH + i];
    }
    free(data);

    /* encode seed using reed-solomon ecc */
    data = malloc(RS_N);
    rs_encode(data, randomness);

    /* xor encoded seed into pseudorandom data stream and loop until
     * no more stream left; seed is protected by one-time pad */
    for( i = 0 ; i < RAMSTAKE_SEEDENC_LENGTH ; ++i )
    {
        c->e[i] ^= data[i % 255];
    }
    free(data);

    /* grab key by completing s and hashing it */
    mpz_add(s, s, b);
    mpz_mod(s, s, p);
    data = malloc(RAMSTAKE_MODULUS_BITSIZE/8);
    mpz_export(data, NULL, 1, 1, 1, 0, s);
    SHA3_256(key, data, RAMSTAKE_MODULUS_BITSIZE/8);

    /* free unfreed variables */
    mpz_clear(p);
    mpz_clear(s);
    mpz_clear(a);
    mpz_clear(b);
    mpz_clear(g);
}

/**
 * ramstake_decaps
 * Decapsulate symmetric key from ramstake ciphertext, and check for
 * manipulation.
 */
int ramstake_decaps( unsigned char * key, ramstake_ciphertext c, ramstake_secret_key sk, int kat )
{
    csprng rng;
    csprng rng2;
    int i;
    mpz_t g, p;
    mpz_t s;
    unsigned char * data;
    unsigned char word[RAMSTAKE_SEEDENC_LENGTH];
    unsigned char seed[RAMSTAKE_SEED_LENGTH];
    ramstake_public_key pk;
    ramstake_ciphertext rec;

    /* initialize pk object */
    ramstake_public_key_init(&pk);

    /* recreate the csprng from keygen */
    csprng_init(&rng);
    csprng_seed(&rng, RAMSTAKE_SEED_LENGTH, sk.seed);

    /* initialize modulus */
    mpz_init(p);
    ramstake_modulus_init(p);

    /* recreate g seed from sk seed */
    mpz_init(g);
    data = malloc(RAMSTAKE_SEED_LENGTH);
    csprng_generate(&rng, RAMSTAKE_SEED_LENGTH, data);
    csprng_init(&rng2);
    csprng_seed(&rng2, RAMSTAKE_SEED_LENGTH, data);
    free(data);
    
    for( i = 0 ; i < RAMSTAKE_SEED_LENGTH ; ++i )
    {
        pk.seed[i] = data[i];
    }

    /* generate data stream integer s = da mod p */
    mpz_init(s);
    mpz_mul(s, c.d, sk.a);
    mpz_mod(s, s, p);
    
    /* turn noisy-shared integer s into noisy-shared data stream */
    data = malloc(RAMSTAKE_MODULUS_BITSIZE/8);
    mpz_export(data, NULL, 1, 1, 1, 0, s);

    for( i = 0 ; i < RAMSTAKE_SEEDENC_LENGTH ; ++i )
    {
        word[i] = data[RAMSTAKE_MODULUS_BITSIZE/8 - RAMSTAKE_SEEDENC_LENGTH + i];
    }
    free(data);

    /* xor encoded string e into our noisy codeword */
    for( i = 0 ; i < RAMSTAKE_SEEDENC_LENGTH ; ++i )
    {
        word[i] ^= c.e[i];
    }

    /* decode any one of the codewords */
    for( i = 0 ; i < RAMSTAKE_CODEWORD_NUMBER ; ++i )
    {
        if( rs_decode(seed, word + i*255) == 0 )
        {
            break;
        }
    }
    if( i == RAMSTAKE_CODEWORD_NUMBER ) /* no word was decodable */
    {
        mpz_clear(g);
        mpz_clear(p);
        mpz_clear(s);
        ramstake_public_key_destroy(pk);
        return -1; /* decapsulation failure */
    }

    /* now we have the seed that generated the ciphertext, let's see
     * if we can recreate the entire thing */
    ramstake_ciphertext_init(&rec);
    mpz_mul(pk.c, g, sk.a);
    mpz_add(pk.c, pk.c, sk.b);
    mpz_mod(pk.c, pk.c, p);
    ramstake_encaps(&rec, key, pk, seed, kat);

    /* decide whether the entire recreated ciphertext is identical */
    if( mpz_cmp(rec.d, c.d) == 0 && strncmp(rec.e, c.e, RAMSTAKE_SEEDENC_LENGTH) == 0 )
    {
        mpz_clear(g);
        mpz_clear(p);
        mpz_clear(s);
        ramstake_public_key_destroy(pk);
        ramstake_ciphertext_destroy(rec);
        return 0; /* success */
    }
    else
    {
        mpz_clear(g);
        mpz_clear(p);
        mpz_clear(s);
        ramstake_public_key_destroy(pk);
        ramstake_ciphertext_destroy(rec);
        return -2; /* forgery attempt */
    }
}

/**
 * ramstake_sample_small_sparse_integer
 * Sample a small-and-sparse integer at random using the given seed.
 */
void ramstake_sample_small_sparse_integer( mpz_t integer, unsigned char * random_seed )
{
    csprng rng;
    int i;
    unsigned long int uli;
    mpz_t difference;

    mpz_init(difference);

    csprng_init(&rng);
    csprng_seed(&rng, RAMSTAKE_SEED_LENGTH, random_seed);
    
    mpz_set_ui(integer, 1);
    mpz_mul_2exp(integer, integer, RAMSTAKE_SECRET_BITSIZE);

    for( i = 0 ; i < RAMSTAKE_SECRET_SPARSITY ; ++i )
    {
        uli = csprng_generate_ulong(&rng);
        mpz_set_ui(difference, 1);
        mpz_mul_2exp(difference, difference, (uli >> 1) % RAMSTAKE_SECRET_BITSIZE);
        if( uli % 2 == 1 )
        {
            mpz_sub(integer, integer, difference);
        }
        else
        {
            mpz_add(integer, integer, difference);
        }
    }

    mpz_clear(difference);
}

/**
 * ramstake_modulus_init
 * Initialize modulus to fixed value
 */
void ramstake_modulus_init( mpz_t p )
{
    mpz_t difference;

    mpz_init(difference);

    /* set modulus p to p = 2^bitsize - difference */
#if RAMSTAKE_MODULUS_BITSIZE == 22040 
    mpz_set_ui(difference, 2325); 
#elif RAMSTAKE_MODULUS_BITSIZE == 16352
    mpz_set_ui(difference, 28169); 
#endif
    mpz_set_ui(p, 1);
    mpz_mul_2exp(p, p, RAMSTAKE_MODULUS_BITSIZE);
    mpz_sub(p, p, difference);

    mpz_clear(difference);
}
void ramstake_modulus_destroy( mpz_t p )
{
    mpz_clear(p);
};

/**
 * ramstake_secret_key_init
 * Initialize ramstake secret key object.
 */
void ramstake_secret_key_init( ramstake_secret_key * sk )
{
    mpz_init(sk->a);
    mpz_init(sk->b);
}
void ramstake_secret_key_destroy( ramstake_secret_key sk )
{
    mpz_clear(sk.a);
    mpz_clear(sk.b);
}

void ramstake_public_key_init( ramstake_public_key * pk )
{
    mpz_init(pk->c);
}
void ramstake_public_key_destroy( ramstake_public_key pk )
{
    mpz_clear(pk.c);
}
void ramstake_ciphertext_init( ramstake_ciphertext * c )
{
    mpz_init(c->d);
}
void ramstake_ciphertext_destroy( ramstake_ciphertext c )
{
    mpz_clear(c.d);
}

void ramstake_export_secret_key( unsigned char * data, ramstake_secret_key sk );
void ramstake_import_secret_key( ramstake_secret_key * sk, unsigned char * data );
void ramstake_export_public_key( unsigned char * data, ramstake_public_key sk );
void ramstake_import_public_key( ramstake_public_key * sk, unsigned char * data );
void ramstake_export_ciphertext( unsigned char * data, ramstake_ciphertext sk );
void ramstake_import_ciphertext( ramstake_ciphertext * sk, unsigned char * data );

