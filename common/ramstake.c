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

    if( kat >= 1 )
    {
        printf("# ramstake_keygen\n");
        printf("seed: ");
        for( i = 0 ; i < RAMSTAKE_SEED_LENGTH ; ++i )
        {
            printf("%02x", random_seed[i]);
        }
        printf("\n");
    }

    /* record random seed into secret key */
    /* (In theory, the secret key need not contain any other data
     * because it can be generated from this seed. Nevertheless, we
     * include the other data directly for faster computations.) */
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

    if( kat >= 2 )
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

    if( kat >= 2 )
    {
        printf("Sampled short and sparse integers a and b.\n");
        printf("a: ");
        mpz_out_str(stdout, 10, sk->a);
        printf("\nb: ");
        mpz_out_str(stdout, 10, sk->b);
        printf("\n");
    }

    /* compute pk integer c = ag + b mod p */
    mpz_mul(pk->c, g, sk->a);
    mpz_add(pk->c, pk->c, sk->b);
    mpz_mod(pk->c, pk->c, p);

    if( kat >= 2 )
    {
        printf("Computed c = ag + b mod p.\n");
        printf("c: ");
        mpz_out_str(stdout, 10, pk->c);
        printf("\n");
    }

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

    if( kat >= 1 )
    {
        printf("# ramstake_encaps\n");
        printf("seed: ");
        for( i = 0 ; i < RAMSTAKE_SEED_LENGTH ; ++i )
        {
            printf("%02x", randomness[i]);
        }
        printf("\n");
    }

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
    if( kat >= 2 )
    {
        printf("Sampled short and sparse integers a and b.\n");
        printf("a: ");
        mpz_out_str(stdout, 10, a);
        printf("\nb: ");
        mpz_out_str(stdout, 10, b);
        printf("\n");
    }

    /* re-generate g from pk seed */
    csprng_init(&rng2);
    csprng_seed(&rng2, RAMSTAKE_SEED_LENGTH, pk.seed);
    data = malloc(RAMSTAKE_MODULUS_BITSIZE/8);
    csprng_generate(&rng2, RAMSTAKE_MODULUS_BITSIZE/8, data);
    mpz_init(g);
    mpz_import(g, RAMSTAKE_MODULUS_BITSIZE/8, 1, sizeof(unsigned char), 1, 0, data);
    free(data);
    if( kat >= 2 )
    {
        printf("Recreated g from public key seed.\n");
        printf("g: ");
        mpz_out_str(stdout, 10, g);
        printf("\n");
    }

    /* compute d = ag + b mod p */
    mpz_mul(c->d, a, g);
    mpz_add(c->d, c->d, b);
    mpz_mod(c->d, c->d, p);
    if( kat >= 2 )
    {
        printf("Computed d = ag + b mod p.\n");
        printf("d: ");
        mpz_out_str(stdout, 10, c->d);
        printf("\n");
    }

    /* compute local data stream integer s = ca mod p */
    mpz_init(s);
    mpz_mul(s, pk.c, a);
    mpz_mod(s, s, p);
    if( kat >= 2 )
    {
        printf("Computed noisy shared secret integer s = ac mod p.\n");
        printf("pk.c: ");
        mpz_out_str(stdout, 10, pk.c);
        printf("\n");
        printf("p: ");
        mpz_out_str(stdout, 10, p);
        printf("\n");
        printf("s: ");
        mpz_out_str(stdout, 10, s);
        printf("\n");
    }

    /* draw pseudorandom stream from integer */
    data = malloc(RAMSTAKE_MODULUS_BITSIZE/8);
    mpz_export(data, NULL, 1, 1, 1, 0, s);
    /* we only care about the first (most significant) SEEDENC_LENGTH bytes. */
    for( i = 0 ; i < RAMSTAKE_SEEDENC_LENGTH ; ++i )
    {
        c->e[i] = data[i];
    }
    free(data);
    if( kat >= 1 )
    {
        printf("Drew most significant %i bytes from s: ", RAMSTAKE_SEEDENC_LENGTH);
        for( i = 0 ; i < RAMSTAKE_SEEDENC_LENGTH ; ++i )
        {
            printf("%02x", c->e[i]);
        }
        printf("\n");
    }

    /* encode seed using reed-solomon ecc */
    data = malloc(RS_N);
    rs_encode(data, randomness);
    if( kat >= 1 )
    {
        printf("Encoded randomness using Reed-Solomon ECC: ");
        for( i = 0 ; i < RS_N ; ++i )
        {
            printf("%02x", data[i]);
        }
        printf("\n");
    }

    /* xor encoded seed into pseudorandom data stream and loop until
     * no more stream left; seed is protected by one-time pad */
    for( i = 0 ; i < RAMSTAKE_SEEDENC_LENGTH ; ++i )
    {
        c->e[i] ^= data[i % RS_N];
    }
    free(data);
    if( kat >= 1 )
    {
        printf("Applied one-time pad to sequence of %i repetitions of the codeword.\ndata: ", RAMSTAKE_CODEWORD_NUMBER);
        for( i = 0  ; i < RAMSTAKE_SEEDENC_LENGTH ; ++i )
        {
            printf("%02x", c->e[i]);
        }
        printf("\n");
    }

    /* grab key by completing s and hashing it */
    mpz_add(s, s, b);
    mpz_mod(s, s, p);
    data = malloc(RAMSTAKE_MODULUS_BITSIZE/8);
    mpz_export(data, NULL, 1, 1, 1, 0, s);
    SHA3_256(key, data, RAMSTAKE_MODULUS_BITSIZE/8);
    if( kat >= 1 )
    {
        printf("Hashed s into key: ");
        for( i = 0 ; i < RAMSTAKE_KEY_LENGTH ; ++i )
        {
            printf("%02x", key[i]);
        }
        printf("\n");
    }
    free(data);

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
    int decoded_codeword;
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
    data = malloc(RAMSTAKE_SEED_LENGTH);
    csprng_generate(&rng, RAMSTAKE_SEED_LENGTH, data);

    for( i = 0 ; i < RAMSTAKE_SEED_LENGTH ; ++i )
    {
        pk.seed[i] = data[i];
    }
    free(data);
    if( kat >= 1 )
    {
        printf("# ramstake_decaps\n");
        printf("Recreated public key seed for g: ");
        for( i = 0 ; i < RAMSTAKE_SEED_LENGTH ; ++i )
        {
            printf("%02x", pk.seed[i]);
        }
        printf("\n");
    }

    /* re-generate g from pk seed */
    csprng_init(&rng2);
    csprng_seed(&rng2, RAMSTAKE_SEED_LENGTH, pk.seed);
    data = malloc(RAMSTAKE_MODULUS_BITSIZE/8);
    csprng_generate(&rng2, RAMSTAKE_MODULUS_BITSIZE/8, data);
    mpz_init(g);
    mpz_import(g, RAMSTAKE_MODULUS_BITSIZE/8, 1, sizeof(unsigned char), 1, 0, data);
    free(data);

    /* initialize modulus */
    mpz_init(p);
    ramstake_modulus_init(p);

    /* generate data stream integer s = da mod p */
    mpz_init(s);
    mpz_mul(s, c.d, sk.a);
    mpz_mod(s, s, p);
    if( kat >= 2 )
    {
        printf("Computed noisy shared secret integer s = da mod p.\n");
        printf("s: ");
        mpz_out_str(stdout, 10, s);
        printf("\n");
    }
    
    /* turn noisy-shared integer s into noisy-shared data stream */
    data = malloc(RAMSTAKE_MODULUS_BITSIZE/8);
    mpz_export(data, NULL, 1, 1, 1, 0, s);

    for( i = 0 ; i < RAMSTAKE_SEEDENC_LENGTH ; ++i )
    {
        //word[i] = data[RAMSTAKE_MODULUS_BITSIZE/8 - RAMSTAKE_SEEDENC_LENGTH + i];
        word[i] = data[i];
    }
    free(data);
    if( kat >= 1 )
    {
        printf("Drew most significant %i bytes from s: ", RAMSTAKE_SEEDENC_LENGTH);
        for( i = 0 ; i < RAMSTAKE_SEEDENC_LENGTH ; ++i )
        {
            printf("%02x", word[i]);
        }
        printf("\n");
    }

    /* xor encoded string e into our noisy codeword */
    for( i = 0 ; i < RAMSTAKE_SEEDENC_LENGTH ; ++i )
    {
        word[i] ^= c.e[i];
    }
    if( kat >= 1 )
    {
        printf("Undid one-time pad: ");
        for( i = 0 ; i < RAMSTAKE_SEEDENC_LENGTH ; ++i )
        {
            printf("%02x", word[i]);
        }
        printf("\n");
    }

    /* decode any one of the codewords */
    for( i = 0 ; i < RAMSTAKE_CODEWORD_NUMBER ; ++i )
    {
        if( rs_decode(seed, word + i*255) == 0 )
        {
            if( kat >= 1 )
            {
                printf("Received word #%i lead to successful decoding.\n", i);
            }
            break;
        }
        else if( kat >= 1 )
        {
            printf("Received word #%i was not decodable.\n", i);
        }
    }
    if( i == RAMSTAKE_CODEWORD_NUMBER ) /* no word was decodable */
    {
        mpz_clear(g);
        mpz_clear(p);
        mpz_clear(s);
        ramstake_public_key_destroy(pk);
        if( kat >= 1 )
        {
            printf("None of the received words were decodable.\n");
        }
        return RAMSTAKE_DECAPSULATION_FAILURE; /* decapsulation failure */
    }
    else
    {
        decoded_codeword = i+1;
    }

    /* now we have the seed that generated the ciphertext, let's see
     * if we can recreate the entire thing */
    ramstake_ciphertext_init(&rec);
    mpz_mul(pk.c, g, sk.a);
    mpz_add(pk.c, pk.c, sk.b);
    mpz_mod(pk.c, pk.c, p);
    ramstake_encaps(&rec, key, pk, seed, 0);

    if( kat >= 2 )
    {
        printf("Re-encapsulating ciphertext from transmitted seed.\n");
        printf("d: ");
        mpz_out_str(stdout, 10, rec.d);
        printf("\n");
        printf("e: ");
        for( i = 0 ; i < RAMSTAKE_SEEDENC_LENGTH ; ++i )
        {
            printf("%02x", rec.e[i]);
        }
        printf("\n");
    }

    /* decide whether the entire recreated ciphertext is identical */
    if( mpz_cmp(rec.d, c.d) == 0 && strncmp(rec.e, c.e, RAMSTAKE_SEEDENC_LENGTH) == 0 )
    {
        mpz_clear(g);
        mpz_clear(p);
        mpz_clear(s);
        ramstake_public_key_destroy(pk);
        ramstake_ciphertext_destroy(rec);
        return decoded_codeword; /* success */
    }
    else
    {
        mpz_clear(g);
        mpz_clear(p);
        mpz_clear(s);
        ramstake_public_key_destroy(pk);
        ramstake_ciphertext_destroy(rec);
        return RAMSTAKE_INTEGRITY_FAILURE; /* forgery attempt */
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
/**
 * ramstake_secret_key_destroy
 * Deallocate space occupied by the given secret key.
 */
void ramstake_secret_key_destroy( ramstake_secret_key sk )
{
    mpz_clear(sk.a);
    mpz_clear(sk.b);
}

/**
 * ramstake_public_key_init
 * Initialize a ramstake public key object.
 */
void ramstake_public_key_init( ramstake_public_key * pk )
{
    mpz_init(pk->c);
}
/**
 * ramstake_public_key_destroy
 * Deallocate space occupied by the given public key object.
 */
void ramstake_public_key_destroy( ramstake_public_key pk )
{
    mpz_clear(pk.c);
}

/**
 * ramstake_ciphertext_init
 * Initialize a ramstake ciphertext object.
 */
void ramstake_ciphertext_init( ramstake_ciphertext * c )
{
    mpz_init(c->d);
}

/**
 * ramstake_ciphertext_destroy
 * Deallocate space occupied by a ramstake ciphertet object.
 */
void ramstake_ciphertext_destroy( ramstake_ciphertext c )
{
    mpz_clear(c.d);
}

/**
 * ramstake_export_secret_key
 * Turn the ramstake secret key into a string of bytes. The
 * destination buffer "data" should be at least
 * RAMSTAKE_SECRET_KEY_LENGTH bytes long.
 */
void ramstake_export_secret_key( unsigned char * data, ramstake_secret_key sk )
{
   int i;

   /* copy seed */
   for( i = 0 ; i < RAMSTAKE_SEED_LENGTH ; ++i )
   {
       data[i] = sk.seed[i];
   }

   /* copy integers */
   mpz_export(data + RAMSTAKE_SEED_LENGTH, NULL, 1, 1, 1, 0, sk.a);
   mpz_export(data + RAMSTAKE_SEED_LENGTH + RAMSTAKE_MODULUS_BITSIZE/8, NULL, 1, 1, 1, 0, sk.b);
}

/**
 * ramstake_import_secret_key
 * Turn a string of bytes into a ramstake secret key.
 */
void ramstake_import_secret_key( ramstake_secret_key * sk, unsigned char * data )
{
    int i;

    /* copy seed */
    for( i = 0 ; i < RAMSTAKE_SEED_LENGTH ; ++i )
    {
        sk->seed[i] = data[i];
    }

    /* copy integers */
    mpz_import(sk->a, RAMSTAKE_MODULUS_BITSIZE/8, 1, 1, 1, 0, data + RAMSTAKE_SEED_LENGTH);
    mpz_import(sk->b, RAMSTAKE_MODULUS_BITSIZE/8, 1, 1, 1, 0, data + RAMSTAKE_SEED_LENGTH + RAMSTAKE_MODULUS_BITSIZE/8);
}

/**
 * ramstake_export_public_key
 * Turn a ramstake public key object into a string of bytes. The
 * destination buffer "data" should be at least
 * RAMSTAKE_PUBLIC_KEY_LENGTH bytes long.
 */
void ramstake_export_public_key( unsigned char * data, ramstake_public_key pk )
{
    int i;

    /* copy seed */
    for( i = 0 ; i < RAMSTAKE_SEED_LENGTH ; ++i )
    {
        data[i] = pk.seed[i];
    }

    /* copy integer */
    mpz_export(data + RAMSTAKE_SEED_LENGTH, NULL, 1, 1, 1, 0, pk.c);
}

/**
 * ramstake_import_public_key
 * Turn a string of bytes into a ramstake public key.
 */
void ramstake_import_public_key( ramstake_public_key * pk, unsigned char * data )
{
    int i;

    /* copy seed */
    for( i = 0 ; i < RAMSTAKE_SEED_LENGTH ; ++i )
    {
        pk->seed[i] = data[i];
    }

    /* copy integer */
    mpz_import(pk->c, RAMSTAKE_MODULUS_BITSIZE/8, 1, 1, 1, 0, data + RAMSTAKE_SEED_LENGTH);
}

/**
 * ramstake_export_ciphertext
 * Turn a ramstake ciphertext object into a string of bytes. The
 * destination buffer "data" should be at least
 * RAMSTAKE_CIPHERTEXT_LENGTH bytes long.
 */
void ramstake_export_ciphertext( unsigned char * data, ramstake_ciphertext c )
{
    int i;

    /* copy integer */
    mpz_export(data, NULL, 1, 1, 1, 0, c.d);

    /* copy seed encoding */
    for( i = 0 ; i < RAMSTAKE_SEEDENC_LENGTH ; ++i )
    {
        data[i + RAMSTAKE_MODULUS_BITSIZE/8] = c.e[i];
    }
}

/**
 * ramstake_import_ciphertext
 * Turn a string of bytes into a ramstake ciphertext object.
 */
void ramstake_import_ciphertext( ramstake_ciphertext * c, unsigned char * data )
{
    int i;

    /* copy integer */
    mpz_import(c->d, RAMSTAKE_MODULUS_BITSIZE/8, 1, 1, 1, 0, data);

    /* copy seed encoding */
    for( i = 0 ; i < RAMSTAKE_SEEDENC_LENGTH ; ++i )
    {
        c->e[i] = data[i + RAMSTAKE_MODULUS_BITSIZE/8];
    }
}

