#ifndef RAMSTAKE_H
#define RAMSTAKE_H

#include <stdint.h>
#include <gmp.h>

#define RAMSTAKE_SEED_LENGTH 32
#define RAMSTAKE_KEY_LENGTH 32

#define RAMSTAKE_MODULUS_BITSIZE 16352
#define RAMSTAKE_CODEWORD_NUMBER 4
#define RAMSTAKE_SEEDENC_LENGTH (RAMSTAKE_CODEWORD_NUMBER * 255)

#define RAMSTAKE_SECRET_BITSIZE 12264
#define RAMSTAKE_SECRET_SPARSITY 23

typedef struct
{
    unsigned char seed[RAMSTAKE_SEED_LENGTH];
    mpz_t a, b;
} ramstake_secret_key;

typedef struct
{
    unsigned char seed[RAMSTAKE_SEED_LENGTH];
    mpz_t c;
} ramstake_public_key;

typedef struct
{
    mpz_t d;
    unsigned char e[RAMSTAKE_SEEDENC_LENGTH];
} ramstake_ciphertext;

int ramstake_keygen( ramstake_secret_key * sk, ramstake_public_key * pk, unsigned char * random_seed, int kat );
int ramstake_encaps( ramstake_ciphertext * c, unsigned char * key, ramstake_public_key pk, unsigned char * randomness, int kat );
int ramstake_decaps( unsigned char * key, ramstake_ciphertext c, ramstake_secret_key sk, int kat );

void ramstake_sample_small_sparse_integer( mpz_t integer, unsigned char * random_seed );

void ramstake_modulus_init( mpz_t p );
void ramstake_modulus_destroy( mpz_t );
void ramstake_secret_key_init( ramstake_secret_key * sk );
void ramstake_secret_key_destroy( ramstake_secret_key sk );
void ramstake_public_key_init( ramstake_public_key * pk );
void ramstake_public_key_destroy( ramstake_public_key pk );
void ramstake_ciphertext_init( ramstake_ciphertext * c );
void ramstake_ciphertext_destroy( ramstake_ciphertext c );

void ramstake_export_secret_key( unsigned char * data, ramstake_secret_key sk );
void ramstake_import_secret_key( ramstake_secret_key * sk, unsigned char * data );
void ramstake_export_public_key( unsigned char * data, ramstake_public_key sk );
void ramstake_import_public_key( ramstake_public_key * sk, unsigned char * data );
void ramstake_export_ciphertext( unsigned char * data, ramstake_ciphertext sk );
void ramstake_import_ciphertext( ramstake_ciphertext * sk, unsigned char * data );


#endif

