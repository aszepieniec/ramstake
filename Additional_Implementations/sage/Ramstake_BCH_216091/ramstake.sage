load("reedsolomon.sage")
from csprng import csprng
from binascii import hexlify
from CompactFIPS202 import SHA3_256

RAMSTAKE_SEED_LENGTH = 32
RAMSTAKE_KEY_LENGTH = 32

#define RAMSTAKE_MODULUS_BITSIZE 16352
#define RAMSTAKE_SECRET_SPARSITY 23
#define RAMSTAKE_CODEWORD_NUMBER 4

RAMSTAKE_MODULUS_BITSIZE = 22040
RAMSTAKE_CODEWORD_NUMBER = 5
RAMSTAKE_SECRET_SPARSITY = 22

RAMSTAKE_CODEWORD_LENGTH = 255
RAMSTAKE_SEEDENC_LENGTH = (RAMSTAKE_CODEWORD_NUMBER * RAMSTAKE_CODEWORD_LENGTH)
RAMSTAKE_DECAPSULATION_FAILURE = -1
RAMSTAKE_INTEGRITY_FAILURE = -2
RAMSTAKE_ULONG_LENGTH = 8

class ramstake_public_key:
    def __init__( self ):
        self.c = 0

class ramstake_secret_key:
    def __init__( self ):
        self.a = 0
        self.b = 0

class ramstake_ciphertext:
    def __init__( self ):
        self.d = 0
        self.e = bytearray([])

def ramstake_sample_sparse_integer( buff, sparsity ):
    integer = 0
    for i in range(0, sparsity):
        uli = sum([256^j * buff[RAMSTAKE_ULONG_LENGTH*i+j] for j in range(0,RAMSTAKE_ULONG_LENGTH)])
        difference = 2^(uli % RAMSTAKE_MODULUS_BITSIZE)
        integer += difference

    return integer

def ramstake_generate_g( seed ):
    rng = csprng()
    rng.seed(bytearray(seed))
    data = rng.generate(RAMSTAKE_MODULUS_BITSIZE/8)

    g = 0
    for i in range(0,len(data)):
        g = 256*g + data[i]

    return g

def ramstake_keygen( random_seed, kat ):
    # get csprng from seed
    rng = csprng()
    rng.seed(random_seed)

    if kat >= 1:
        print "\n# ramstake_keygen"
        print "seed:", hexlify(random_seed)

    # generate seed for g
    pk = ramstake_public_key()
    pk.seed = rng.generate(RAMSTAKE_SEED_LENGTH)
    g = ramstake_generate_g(pk.seed)
    if kat >= 2:
        print "seed for generating g:", hexlify(pk.seed)
        print "g:", g

    # sample secret integers a and b
    sk = ramstake_secret_key()
    sk.seed = copy(random_seed)
    # sample sparse secret integers
    buff = rng.generate(RAMSTAKE_ULONG_LENGTH * RAMSTAKE_SECRET_SPARSITY)
    sk.a = ramstake_sample_sparse_integer(buff, RAMSTAKE_SECRET_SPARSITY)
    buff = rng.generate(RAMSTAKE_ULONG_LENGTH * RAMSTAKE_SECRET_SPARSITY)
    sk.b = ramstake_sample_sparse_integer(buff, RAMSTAKE_SECRET_SPARSITY)
    if kat >= 2:
        print "Sampled short and sparse integers a and b."
        print "a:", sk.a
        print "b:", sk.b

    # obtain modulus
    p = 2^RAMSTAKE_MODULUS_BITSIZE - 1

    # compute c = ag + b mod p
    pk.c = (g * sk.a + sk.b) % p
    if kat >= 2:
        print "Computed c = ag + b mod p."
        print "c:", pk.c

    return sk, pk

def ramstake_encaps( random_seed, pk, kat ):
    # get csprng from seed
    rng = csprng()
    rng.seed(random_seed)

    if kat >= 0:
        print "\n# ramstake_encaps"
        print "seed:", hexlify(random_seed)

    # sample secret integers a and b
    buff = rng.generate(RAMSTAKE_ULONG_LENGTH * RAMSTAKE_SECRET_SPARSITY)
    a = ramstake_sample_sparse_integer(buff, RAMSTAKE_SECRET_SPARSITY)
    buff = rng.generate(RAMSTAKE_ULONG_LENGTH * RAMSTAKE_SECRET_SPARSITY)
    b = ramstake_sample_sparse_integer(buff, RAMSTAKE_SECRET_SPARSITY)
    if kat >= 3:
        print "Sampled short and sparse integers a and b."
        print "a:", a
        print "b:", b

    # recreate g from pk seed
    g = ramstake_generate_g(pk.seed)
    if kat >= 3:
        print "Recreated g from public key seed."
        print "g:", g

    # obtain modulus
    p = 2^RAMSTAKE_MODULUS_BITSIZE - 1

    # compute d = ag + b mod p
    c = ramstake_ciphertext()
    c.d = (a*g + b) % p
    if kat >= 3:
        print "Computed d = ag + b mod p."
        print "d:", c.d

    # compute s = ac mod p
    s = (a*pk.c) % p
    if kat >= 3:
        print "Computed noisy shared secret integer s = ac mod p."
        print "pk.c:", pk.c
        print "p:", p
        print "s:", s

    # draw most significant SEEDENC_LENGTH bytes from s
    c.e = bytearray(hex(s)[0:(2*RAMSTAKE_SEEDENC_LENGTH)].decode("hex"))
    if kat >= 3:
        print "Drew most significant", RAMSTAKE_SEEDENC_LENGTH, "bytes from s:", hexlify(c.e)

    # encode randomness seed
    rs = ReedSolomon(8, 224)
    data = rs.EncodeBytesMultiple(random_seed, RAMSTAKE_CODEWORD_NUMBER)
    if kat >= 3:
        print "Encoded randomness using Reed-Solomon ECC:", hexlify(data)

    # apply otp to codeword sequence
    for i in range(0, rs.n * RAMSTAKE_CODEWORD_NUMBER):
        c.e[i] = c.e[i] ^^ data[i]
    if kat >= 3:
        print "Applied one-time pad to sequence of", RAMSTAKE_CODEWORD_NUMBER, "repetitions of the codeword."
        print "data:", hexlify(c.e)

    # complete s and hash it to obtain key
    s_ = bytearray(hex(((s + b) % p) + 255*2^RAMSTAKE_MODULUS_BITSIZE)[2:].decode("hex"))
    key = SHA3_256(s_)
    if kat >= 1:
        print "Hashed s into key:", hexlify(key)
        if kat >= 2:
            print "From s:", (((s+b)%p) + 255*2^RAMSTAKE_MODULUS_BITSIZE)

    return c, key

def ramstake_decaps( c, sk, kat ):
    # recreate pk
    pk = ramstake_public_key()
    rng = csprng()
    rng.seed(sk.seed)
    pk.seed = rng.generate(RAMSTAKE_SEED_LENGTH)
    if kat >= 1:
        print "\n# ramstake_decaps"
        print "secret key seed:", hexlify(sk.seed)
        print "Recreated public key seed for g:", hexlify(pk.seed)

    # recreate g
    g = ramstake_generate_g(pk.seed)

    # obtain modulus
    p = 2^RAMSTAKE_MODULUS_BITSIZE - 1

    # compute s = da mod p
    s = (c.d * sk.a) % p
    if kat >= 3:
        print "Computed noisy shared secret integer s = da mod p."
        print "s:", s
        print "from sk.a:", sk.a

    # draw SEEDENC bytes from s
    word = bytearray(hex(s + 2^RAMSTAKE_MODULUS_BITSIZE)[1:(1+2*RAMSTAKE_SEEDENC_LENGTH)].decode("hex"))
    if kat >= 3:
        print "Drew most significant", RAMSTAKE_SEEDENC_LENGTH, "bytes from s:", hexlify(word)

    # undo OTP
    for i in range(0, len(word)):
        word[i] = word[i] ^^ c.e[i]
    if kat >= 3:
        print "Undid one-time pad:", hexlify(word)

    # try to decode
    rs = ReedSolomon(8, 224)
    decoded = rs.DecodeBytesMultiple(word, RAMSTAKE_CODEWORD_NUMBER)
    if decoded == bytearray([0]*rs.k):
        if kat >= 1:
            print "None of the received words were decodable."
        return RAMSTAKE_DECAPSULATION_FAILURE

    # re-create ciphertext
    pk.c = (sk.a * g + sk.b) % p
    rec, key = ramstake_encaps(bytearray(decoded), pk, 0)
    if kat >= 1:
        print "Re-encapsulating ciphertext from transmitted seed."
        print "seed:", hexlify(bytearray(decoded))
    if kat >= 3:
        print "d:", rec.d
        print "e:", hexlify(rec.e)

    if rec.d != c.d or rec.e != c.e:
        if rec.d != c.d:
            print "recreated d =/= ciphertext d"
        if rec.e != c.e:
            print "recreated e =/= ciphertext e"
        return RAMSTAKE_INTEGRITY_FAILURE

    return key

def ramstake_export_secret_key( sk ):
    ret = copy(sk.seed)
    hexa = hex(sk.a)
    hexb = hex(sk.b)
    if len(hexa) % 2 == 1:
        hexa = "0" + hexa
    if len(hexb) % 2 == 1:
        hexb = "0" + hexb
    bytesa = bytearray(list(hexa.decode("hex")))
    bytesb = bytearray(list(hexb.decode("hex")))
    while len(bytesa) != RAMSTAKE_MODULUS_BITSIZE/8:
        bytesa.append(0)
    while len(bytesb) != RAMSTAKE_MODULUS_BITSIZE/8:
        bytesb.append(0)
    ret.extend(bytesa)
    ret.extend(bytesb)
    return ret

