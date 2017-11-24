#include <stdlib.h>
#include <stdio.h>
#include "bch.h"

gf2x bch_minpoly( unsigned int elm )
{
    unsigned char * data;
    unsigned char temp;
    unsigned int * pivots;
    unsigned int * pivot_rows;
    int num_pivots;
    unsigned int * frees;
    int num_frees;
    int col, row, pivot;
    int width, height;
    int i, j;
    unsigned int raised;
    gf2x dest;

    height = 16;
    width = 17;
    data = malloc(height*width);

    /* compile matrix */
    raised = 1;
    for( j = 0 ; j < width ; ++j )
    {
        for( i = 0 ; i < 16 ; ++i )
        {
            if( (raised & (1 << i)) != 0 )
            {
                data[i*width + j] = 1;
            }
            else
            {
                data[i*width + j] = 0;
            }
        }
        for( ; i < height ; ++i )
        {
            data[i*width + j] = 0;
        }
        raised = gf4096_multiply(raised, elm);
    }

    if( 0 == 1 )
    {
        /* print matrix */
        printf("matrix:\n");
        for( i = 0 ; i < height ; ++i )
        {
            printf("[");
            for( j = 0 ; j < width ; ++j )
            {
                printf("%i", data[i*width + j]);
                if( j != width-1 )
                {
                    printf(" ");
                }
            }
            printf("]\n");
        }
    }   

    /* reduce to echelon */
    pivots = malloc(sizeof(unsigned int)*width);
    pivot_rows = malloc(sizeof(unsigned int)*width);
    num_pivots = 0;
    frees = malloc(sizeof(unsigned int)*width);
    num_frees = 0;
    row = 0;
    for( col = 0 ; col < width ; ++col )
    {
        /* if not pivot element */
        if( data[row*width + col] != 1 )
        {
            /* find pivot element */
            for( pivot = row + 1 ; pivot < height ; ++pivot )
            {
                if( data[pivot*width + col] == 1 )
                {
                    break;
                }
            }
            /* if no pivot element, mark free */
            if( pivot == height )
            {
                frees[num_frees++] = col;
                continue;
            }
            /* otherwise swap rows */
            for( i = 0 ; i < width ; ++i )
            {
                temp = data[row*width + i];
                data[row*width + i] = data[pivot*width + i];
                data[pivot*width + i] = temp;
            }
        }

        /* clear pivot column */
        for( i = 0 ; i < height ; ++i )
        {
            /* skip working row */
            if( i == row )
            {
                continue;
            }

            /* if element at (i, col) is nonzero, add working row */
            if( data[i*width + col] == 1 )
            {
                for( j = col ; j < width ; ++j )
                {
                    data[i*width + j] ^= data[row*width + j];
                }
            }
        }

        /* mark as pivot and increase working row */
        pivot_rows[num_pivots] = row;
        pivots[num_pivots] = col;
        num_pivots += 1;
        row += 1;

        /* if we had all rows, mark the remaining columns as frees and break */
        if( row == height )
        {
            for( i = col + 1 ; i < width ; ++i )
            {
                frees[num_frees++] = i;
            }
            break;
        }
    }

    /* minpoly = kernel vector associated with first free variable */
    dest = gf2x_init(frees[0]);
    for( i = 0 ; i < (dest.degree+1+7)/8 ; ++i )
    {
        dest.data[i] = 0;
    }
    dest.data[frees[0]/8] ^= 1 << (frees[0] % 8);
    for( i = 0 ; i < num_pivots ; ++i )
    {
        if( pivots[i] > frees[0] )
        {
            break;
        }
        dest.data[pivot_rows[i]/8] ^= data[pivot_rows[i]*width + frees[0]] << (pivot_rows[i] % 8);
    }

    /* clean up */
    free(data);
    free(pivots);
    free(pivot_rows);
    free(frees);

    return dest;
}
 

/**
 * bch_init
 * Create a BCH codec object, including generator polynomial and
 * parameters inferred from n and delta. (Subject to m=12).
 */
bch bch_init( unsigned int n, unsigned int delta )
{
    int i, j;
    gf2x * list;
    unsigned int elm;
    unsigned int list_size;
    bch codec;
    gf2x temp1, temp2, temp3, temp4;

    /* populate list */
    list_size = 0;
    list = malloc(sizeof(gf2x)*delta);
    elm = 1;
    for( i = 0 ; i < delta-1 ; ++i )
    {
        elm = gf4096_multiply(elm, BCH_FIELD_GEN);
        list[i] = bch_minpoly(elm);
    }
    list_size = delta-1;

    /* collapse list */
    while( list_size != 1 )
    {
        j = 0;
        for( i = 0 ; i < list_size-1 ; i += 2 )
        {
            gf2x_lcm(&list[j], list[i], list[i+1]);
            if( gf2x_divides(list[i], list[j]) == 0 || gf2x_divides(list[i+1], list[j]) == 0 )
            {
                printf("ERROR! factors do not divide lcm!\n");
                printf("lhs: "); gf2x_print(list[i]); printf("\n");
                printf("rhs: "); gf2x_print(list[i+1]); printf("\n");
                printf("lcm: "); gf2x_print(list[j]); printf("\n");
                temp1 = gf2x_init(0);
                gf2x_gcd(&temp1, list[i], list[i+1]);
                printf("gcd: "); gf2x_print(temp1); printf("\n");
                temp2 = gf2x_init(0);
                gf2x_multiply(&temp2, list[i], list[i+1]);
                printf("product: "); gf2x_print(temp2); printf("\n");
                temp3 = gf2x_init(0);
                temp4 = gf2x_init(0);
                gf2x_divide(&temp3, &temp4, temp2, temp1);
                printf("quotient: "); gf2x_print(temp3); printf("\n");
                printf("remainder: "); gf2x_print(temp4); printf("\n");
                gf2x_destroy(temp1);
                gf2x_destroy(temp2);
                gf2x_destroy(temp3);
                gf2x_destroy(temp4);
            }
            j += 1;
        }
        if( i == list_size - 1 )
        {
            gf2x_copy(&list[j++], list[i]);
        }
        for( i = j ; i < list_size ; ++i )
        {
            gf2x_destroy(list[i]);
        }
        list_size = j;
    }
    codec.generator = list[0];
    free(list);

    /* infer remaining parameters */
    codec.n = n;
    codec.delta = delta;
    codec.t = (delta-1)/2;
    codec.k = n - codec.generator.degree;

    return codec;
}
 

/**
 * bch_init
 * Create a BCH codec object, including generator polynomial and
 * parameters inferred from k and n. (Subject to m=12). Optimize
 * delta.
 */
bch bch_init_kn( unsigned int k, unsigned int n )
{
    int i, j;
    unsigned int elm;
    bch codec;
    gf2x temp1, temp2, temp3, temp4;
    gf2x multiple, minpoly;

    /* get generator */
    codec.generator = gf2x_init(0);
    gf2x_one(&codec.generator);
    multiple = gf2x_init(0);
    elm = 1;
    for( i = 1 ; i < n ; ++i )
    {
        elm = gf4096_multiply(elm, BCH_FIELD_GEN);
        minpoly = bch_minpoly(elm);
        gf2x_lcm(&multiple, minpoly, codec.generator);
        gf2x_destroy(minpoly);
        if( multiple.degree + k > n )
        {
            break;
        }
        gf2x_copy(&codec.generator, multiple);
    }

    /* infer remaining parameters */
    codec.n = n;
    codec.delta = i - 1;
    codec.t = (codec.delta-1)/2;
    codec.k = k;

    gf2x_destroy(multiple);

    return codec;
}

/**
 * bch_destroy
 * Deallocate memory reserved for the codec object.
 */
int bch_destroy( bch codec )
{
    gf2x_destroy(codec.generator);
    return 1;
}

/**
 * bch_encode
 * Encode a string of bits into a codeword. The message is length is
 * k and if k is not divisible by 8 the last byte uses the least 
 * significant bits. The codeword length is n and if n is not
 * divisible by 8 then the last byte uses the least significant bits.
 * This function assumes enough space has already been allocated in
 * codeword.
 */
int bch_encode( unsigned char * codeword, bch codec, unsigned char * message )
{
    gf2x cdwd;
    gf2x msg;
    int i;

    msg.degree = codec.k-1;
    msg.data = message;
    gf2x_trim(&msg);

    cdwd = gf2x_init(0);
    gf2x_multiply(&cdwd, codec.generator, msg);

    for( i = 0 ; i < (cdwd.degree+1+7)/8 ; ++i )
    {
        codeword[i] = cdwd.data[i];
    }
    for( ; i < (codec.n+1+7)/8 ; ++i )
    {
        codeword[i] = 0;
    }
    gf2x_destroy(cdwd);

    return 1;
}

/**
 * bch_interrupted_euclid
 * Use the interrupted euclidean procedure to get the error locator
 * polynomial.
 */
int bch_interrupted_euclid( gf4096x * sigma, gf4096x * omega, gf4096x syndrome, gf4096x gcap )
{
    gf4096x s1, s2;
    gf4096x t1, t2;
    gf4096x r1, r2;
    gf4096x quotient, remainder;
    gf4096x temp;
    gf4096x temp2;
    unsigned int lc;

    s1 = gf4096x_init(0);
    s2 = gf4096x_init(0);
    t1 = gf4096x_init(0);
    t2 = gf4096x_init(0);
    r1 = gf4096x_init(0);
    r2 = gf4096x_init(0);
    quotient = gf4096x_init(0);
    remainder = gf4096x_init(0);
    temp = gf4096x_init(0);
    temp2 = gf4096x_init(0);

    gf4096x_zero(&s1);
    gf4096x_one(&s2);
    gf4096x_one(&t1);
    gf4096x_zero(&t2);
    gf4096x_copy(&r1, gcap);
    gf4096x_copy(&r2, syndrome);

    while( r2.degree >= t2.degree )
    {
        gf4096x_divide(&quotient, &remainder, r1, r2);

        gf4096x_copy(&r1, r2);
        gf4096x_copy(&r2, remainder);

        gf4096x_multiply(&temp, quotient, s2);
        gf4096x_add(&temp, temp, s1);
        gf4096x_copy(&s1, s2);
        gf4096x_copy(&s2, temp);

        gf4096x_multiply(&temp, quotient, t2);
        gf4096x_add(&temp, temp, t1);
        gf4096x_copy(&t1, t2);
        gf4096x_copy(&t2, temp);
    }

    gf4096x_copy(sigma, s1);
    gf4096x_copy(omega, r1);

    gf4096x_destroy(s1);
    gf4096x_destroy(s2);
    gf4096x_destroy(t1);
    gf4096x_destroy(t2);
    gf4096x_destroy(r1);
    gf4096x_destroy(r2);
    gf4096x_destroy(quotient);
    gf4096x_destroy(remainder);
    gf4096x_destroy(temp);
    gf4096x_destroy(temp2);

    return 1;
}

/**
 * bch_syndrome
 * Compute the syndrome of the received noisy codeword.
 * This function returns a new gf4096x object; please don't forget
 * to destroy it.
 */
gf4096x bch_syndrome( bch codec, unsigned char * word )
{
    gf4096x syndrome;
    unsigned int ev, z, zi, zij;
    int i, j;

    z = BCH_FIELD_GEN;
    syndrome = gf4096x_init(codec.delta-2);
    zi = 1;
    for( i = 0 ; i < codec.delta-1 ; ++i )
    {
        ev = 0;
        zi = gf4096_multiply(zi, z);
        zij = 1;
        for( j = 0 ; j < codec.n ; ++j )
        {
            if( (word[j/8] & (1 << (j%8))) != 0 )
            {
                ev ^= zij;
            }
            zij = gf4096_multiply(zij, zi);
        }
        syndrome.data[2*i] = ev & 0xff;
        syndrome.data[2*i+1] = (ev >> 8) & 0xff;
    }

    return syndrome;
}

/**
 * bch_decode_syndrome
 * Determine the errors from the syndrome. This function flips the
 * erroneous bits in the given buffer, so you can use it for
 * error location by giving it an all-zero buffer or for error
 * correction by giving it the noisy codeword. In either case, the 
 * buffer should be large enough to hold at least n bits.
 */
int bch_decode_syndrome( unsigned char * errors, bch codec, gf4096x syndrome )
{
    gf4096x g;
    gf4096x sigma, omega;
    int i, j;
    unsigned int zinv, zmini, zminij;
    unsigned int ev1, ev2, coeff;

    g = gf4096x_init(0);
    gf4096x_one(&g);
    gf4096x_multiply_constant_shift(&g, g, 1, codec.delta);

    sigma = gf4096x_init(0);
    omega = gf4096x_init(0);
    bch_interrupted_euclid(&sigma, &omega, syndrome, g);
    gf4096x_destroy(g);


    zinv = gf4096_inverse(BCH_FIELD_GEN);
    zmini = 1;
    for( i = 0 ; i < codec.n ; ++i )
    {
        ev1 = 0;
        zminij = 1;
        for( j = 0 ; j < sigma.degree + 1 ; ++j )
        {
            coeff = ((unsigned int)(sigma.data[2*j+1]) << 8) ^ sigma.data[2*j];
            ev1 ^= gf4096_multiply(coeff, zminij);
            zminij = gf4096_multiply(zmini, zminij);
        }
        ev2 = gf4096x_eval(sigma, zmini);
        if( ev2 == 0 )
        {
            errors[i/8] ^= (1 << (i%8));
        }
        zmini = gf4096_multiply(zmini, zinv);
    }

    gf4096x_destroy(sigma);
    gf4096x_destroy(omega);

    return 1;
}

/**
 * bch_decode_error_free
 * Assuming the codeword is error-free, compute the matching message.
 * This function assumes enough space has already been allocated for
 * message.
 */
int bch_decode_error_free( unsigned char * message, bch codec, unsigned char * codeword )
{
    gf2x cdwd, quo, rem;
    int i;
    int success;

    cdwd.degree = codec.n;
    cdwd.data = codeword;
    gf2x_trim(&cdwd);

    quo = gf2x_init(0);
    rem = gf2x_init(0);
    gf2x_divide(&quo, &rem, cdwd, codec.generator);
    success = gf2x_is_zero(rem);

    for( i = 0 ; i < (quo.degree+1+7)/8 ; ++i )
    {
        message[i] = quo.data[i];
    }
    for( ; i < (codec.k+1+7)/8 ; ++i )
    {
        message[i] = 0;
    }
    gf2x_destroy(quo);
    gf2x_destroy(rem);

    return success;
}

/**
 * bch_decode
 * Take a noisy codeword and (if the noise level is not too large)
 * output the message that generated it.
 */
int bch_decode( unsigned char * message, bch codec, unsigned char * codeword )
{
    gf4096x syndrome;
    unsigned char * errata;
    unsigned char * cdwd;
    int success;
    int i;


    syndrome = bch_syndrome(codec, codeword);
    if( gf4096x_is_zero(syndrome) == 1 )
    {
        gf4096x_destroy(syndrome);
        return bch_decode_error_free(message, codec, codeword);
    }

    errata = malloc((codec.n+1+7)/8);
    for( i = 0 ; i < (codec.n+1+7)/8 ; ++i )
    {
        errata[i] = 0;
    }
    success = bch_decode_syndrome(errata, codec, syndrome);

    cdwd = malloc((codec.n+1+7)/8);
    for( i = 0 ; i < (codec.n+1+7)/8 ; ++i )
    {
        cdwd[i] = codeword[i] ^ errata[i];
    }

    bch_decode_error_free(message, codec, cdwd);
    
    free(errata);
    free(cdwd);
    gf4096x_destroy(syndrome);
    return success;
}

