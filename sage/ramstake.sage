load("reedsolomon.sage")
from csprng import csprng
from binascii import hexlify
from CompactFIPS202 import SHA3_256

RAMSTAKE_SEED_LENGTH = 32
RAMSTAKE_KEY_LENGTH = 32
RAMSTAKE_MODULUS_BITSIZE = 16352
RAMSTAKE_SECRET_BITSIZE = 12264
RAMSTAKE_SECRET_SPARSITY = 23
RAMSTAKE_CODEWORD_NUMBER = 4
RAMSTAKE_CODEWORD_LENGTH = 255
RAMSTAKE_SEEDENC_LENGTH = (RAMSTAKE_CODEWORD_NUMBER * RAMSTAKE_CODEWORD_LENGTH)

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

def ramstake_sample_small_sparse_integer( seed ):
    rng = csprng()
    rng.seed(bytearray(seed))

    integer = 2^RAMSTAKE_SECRET_BITSIZE

    for i in range(0, RAMSTAKE_SECRET_SPARSITY):
        r = rng.generate(8)
        uli = sum([256^i * r[i] for i in range(0,len(r))])
        difference = 2^((uli >> 1) % RAMSTAKE_SECRET_BITSIZE)
        if uli % 2 == 1:
            integer -= difference
        else:
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

    if kat == 1:
        print "# ramstake_keygen"
        print "seed:", hexlify(random_seed)

    # obtain modulus
    p = 2^RAMSTAKE_MODULUS_BITSIZE
    if RAMSTAKE_MODULUS_BITSIZE == 16352:
        p -= 28169
    elif RAMSTAKE_MODULUS_BITSIZE == 22040:
        p -= 2325

    # generate seed for g
    pk = ramstake_public_key()
    pk.seed = rng.generate(RAMSTAKE_SEED_LENGTH)
    g = ramstake_generate_g(pk.seed)
    if kat == 1:
        print "seed for generating g:", hexlify(pk.seed)
        print "g:", g

    # sample secret integers a and b
    sk = ramstake_secret_key()
    sk.seed = copy(random_seed)
    sk.a = ramstake_sample_small_sparse_integer(rng.generate(RAMSTAKE_SEED_LENGTH))
    sk.b = ramstake_sample_small_sparse_integer(rng.generate(RAMSTAKE_SEED_LENGTH))
    if kat == 1:
        print "Sampled short and sparse integers a and b."
        print "a:", sk.a
        print "b:", sk.b

    # compute c = ag + b mod p
    pk.c = (g * sk.a + sk.b) % p
    if kat == 1:
        print "Computed c = ag + b mod p."
        print "c:", pk.c

    return sk, pk

def ramstake_encaps( random_seed, pk, kat ):
    # get csprng from seed
    rng = csprng()
    rng.seed(random_seed)

    if kat == 1:
        print "# ramstake_encaps"
        print "seed:", hexlify(random_seed)

    # sample secret integers a and b
    a = ramstake_sample_small_sparse_integer(rng.generate(RAMSTAKE_SEED_LENGTH))
    b = ramstake_sample_small_sparse_integer(rng.generate(RAMSTAKE_SEED_LENGTH))
    if kat == 1:
        print "Sampled short and sparse integers a and b."
        print "a:", a
        print "b:", b

    # recreate g from pk seed
    g = ramstake_generate_g(pk.seed)
    if kat == 1:
        print "Recreated g from public key seed."
        print "g:", g

    # obtain modulus
    p = 2^RAMSTAKE_MODULUS_BITSIZE
    if RAMSTAKE_MODULUS_BITSIZE == 16352:
        p -= 28169
    elif RAMSTAKE_MODULUS_BITSIZE == 22040:
        p -= 2325

    # compute d = ag + b mod p
    c = ramstake_ciphertext()
    c.d = (a*g + b) % p
    if kat == 1:
        print "Computed d = ag + b mod p."
        print "d:", c.d

    # compute s = ac mod p
    s = (a*pk.c) % p
    if kat == 1:
        print "Computed noisy shared secret integer s = ac mod p."
        print "pk.c:", pk.c
        print "p:", p
        print "s:", s

    # draw most significant SEEDENC_LENGTH bytes from s
    c.e = bytearray(hex(s)[0:(2*RAMSTAKE_SEEDENC_LENGTH)].decode("hex"))
    if kat == 1:
        print "Drew most significant", RAMSTAKE_SEEDENC_LENGTH, "bytes from s:", hexlify(c.e)

    # encode randomness seed
    rs = ReedSolomon(8, 224)
    data = rs.EncodeBytes(random_seed)
    if kat == 1:
        print "Encoded randomness using Reed-Solomon ECC:", hexlify(data)

    # apply otp to codeword sequence
    for i in range(0, RAMSTAKE_CODEWORD_NUMBER):
        for j in range(0, rs.n):
            c.e[i*rs.n + j] = c.e[i*rs.n + j] ^^ data[j]
    if kat == 1:
        print "Applied one-time pad to sequence of", RAMSTAKE_CODEWORD_NUMBER, "repetitions of the codeword."
        print "data:", hexlify(c.e)

    # complete s and hash it to obtain key
    s_ = bytearray(hex((s + b) % p).decode("hex"))
    key = SHA3_256(s_)
    if kat == 1:
        print "Hashed s into key:", hexlify(key)

    return c, key

def ramstake_decaps( c, sk, kat ):
    # recreate pk
    pk = ramstake_public_key()
    rng = csprng()
    rng.seed(sk.seed)
    pk.seed = rng.generate(RAMSTAKE_SEED_LENGTH)
    if kat == 1:
        print "# ramstake_decaps"
        print "Recreated public key seed for g:", hexlify(pk.seed)

    # recreate g
    g = ramstake_generate_g(pk.seed)

    # obtain modulus
    p = 2^RAMSTAKE_MODULUS_BITSIZE
    if RAMSTAKE_MODULUS_BITSIZE == 16352:
        p -= 28169
    elif RAMSTAKE_MODULUS_BITSIZE == 22040:
        p -= 2325

    # compute s = da mod p
    s = (c.d * sk.a) % p
    if kat == 1:
        print "Computed noisy shared secret integer s = da mod p."
        print "s:", s

    # draw SEEDENC bytes from s
    word = bytearray(hex(s)[0:(2*RAMSTAKE_SEEDENC_LENGTH)].decode("hex"))
    if kat == 1:
        print "Drew most significant", RAMSTAKE_SEEDENC_LENGTH, "bytes from s:", hexlify(word)

    # undo OTP
    for i in range(0, len(word)):
        word[i] = word[i] ^^ c.e[i]
    if kat == 1:
        print "Undid one-time pad:", hexlify(word)

    # try to decode
    rs = ReedSolomon(8, 224)
    for i in range(0, RAMSTAKE_CODEWORD_NUMBER):
        decoded = bytearray(rs.DecodeBytes(word[(i*RAMSTAKE_CODEWORD_LENGTH):((i+1)*RAMSTAKE_CODEWORD_LENGTH)]))
        if decoded != [0]*rs.k:
            if kat == 1:
                print "Received word #%i lead to successful decoding." % i
            break
        elif kat == 1:
            print "Received word #%i was not decodable." % i

    if decoded == [0]*rs.k:
        if kat == 1:
            print "None of the received words were decodable."
        return -1

    print "decoded:", hexlify(decoded)

    # re-create ciphertext
    pk.c = (sk.a * g + sk.b) % p
    rec, key = ramstake_encaps(decoded, pk, 0)
    if kat == 1:
        print "Re-encapsulating ciphertext from transmitted seed."
        print "d:", rec.d
        print "e:", hexlify(rec.e)

    if rec.d != c.d or red.e != c.e:
        return -2

    return 0

def Parameters( security_level ):
    kappa = 2*security_level
    bitsize = 50000
    #kappa = 823
    q = 2^bitsize - 7
    sparsity = 27
    burst_length = 1

    return (kappa, bitsize, q, sparsity, burst_length)

def Init( params ):
    kappa, bitsize, q, sparsity, burst_length = params
    return ZZ(Integers(q).random_element())

def RandomSparseInteger( bitbudget, sparsity ):
    acc = 2^bitbudget
    ZZb = Integers(bitbudget)
    for i in range(1, sparsity):
        acc += 2^ZZ(ZZb.random_element())
    return acc

def RandomBurst( burst_length ):
    acc = 2^burst_length
    for i in range(0, burst_length-1):
        acc = acc + ZZ(Integers(2).random_element()) * 2^i
    return acc

def RandomSparseBurstInteger( bitbudget, sparsity, burst_length ):
    acc = 2^bitbudget + RandomBurst(burst_length)*2^(bitbudget-burst_length)
    for j in range(0, sparsity):
        burst = RandomBurst(burst_length)
        index = Integers(bitbudget).random_element()
        if ZZ(Integers(2).random_element()) == 1:
            acc += 2^(bitbudget-index) * burst
        else:
            acc -= 2^(bitbudget-index) * burst
    return acc

def GF_to_int( gfelm ):
    coeffs = gfelm.polynomial().coefficients(sparse=False)
    a = 0
    for i in range(0,len(coeffs)):
        a += ZZ(coeffs[i])*2^i
    return a

def Argue( params, g ):
    kappa, bitsize, q, sparsity, burst_length = params
    x = RandomSparseBurstInteger(ceil(3.0*bitsize/4), sparsity, burst_length)
    y = RandomSparseBurstInteger(ceil(3.0*bitsize/4), sparsity, burst_length)
    return (x, (g*x + y) % q)

def Agree( params, secret, contribution ):
    kappa, bitsize, q, sparsity, burst_length = params
    z = (contribution * secret) % q
    return (z >> ceil(kappa / 2)) + 2^ceil(kappa/2)

def CastBits( bits, field ):
    array = []
    z = field.gen()
    for i in range(0, ceil(len(bits)/field.degree())):
        elm = field(0)
        for j in range(0, field.degree()):
            if i*field.degree() + j >= len(bits):
                break
            if bits[i*field.degree() + j] == '1':
                elm += z^j
        array.append(elm)
    return array

def KeyGen( params ):
    kappa, bitsize, q, sparsity, burst_length = params
    field_degree = 12
    rs = ReedSolomon(field_degree, 2^field_degree-1-ceil(kappa/field_degree))
    print "generated reed solomon code with n=", rs.n, "and k=", rs.k
    g = Init(params)
    As, Ac = Argue(params, g)
    pk = (g, Ac, rs)
    sk = (g, As, rs)
    return (pk, sk)

def Enc( params, pk ):
    kappa, bitsize, q, sparsity, burst_length = params
    g, Ac, rs = pk
    Bs, Bc = Argue(params, g)
    Bz = Agree(params, Bs, Ac)
    bits = bin(Bz)[2:(2+rs.n*rs.F.degree())]
    print "length of bitstring:", len(bits)
    symbols = CastBits(bits, rs.F)
    if len(symbols) < rs.n:
        print "problem: have fewer OTP symbols than length of codeword!"
        print "number of OTP symbols:", len(symbols)
        print "length of codeword:", rs.n
    key = [rs.F.random_element() for i in range(0,rs.k)]
    codeword = rs.Encode(key)
    xor = [symbols[i] + codeword[i] for i in range(0,min(rs.n, len(codeword)))]
    ctxt = (Bc, xor)
    return (ctxt, key, symbols)

def Dec( params, sk, ctxt ):
    kappa, bitsize, q, sparsity, burst_length = params
    g, As, rs = sk
    Bc, xor = ctxt

    Az = Agree(params, As, Bc)
    bits = bin(Az)[2:(2+rs.n*rs.F.degree())]
    print "length of bitstring:", len(bits)
    symbols = CastBits(bits, rs.F)
    rec = [symbols[i] + xor[i] for i in range(0,rs.n)]
    
    key = rs.Decode(rec)
    return (key, symbols)

def TestKeyEncapsulation():
    params = Parameters(128)
    kappa, bitsize, q, sparsity, burst_length = params

    print "testing key encapsulation with q approx. 2^%i, sparsity = %i and burst length = %i" % (bitsize, sparsity, burst_length)
    print "total entropy in secret integers:", (log(1.0*binomial(ceil(3.0/4)*bitsize, sparsity), 2.0) + (sparsity+1)*(burst_length-1))

    pk, sk = KeyGen(params)
    g, Ac, rs = pk
    ctxt, keya, symbolsa = Enc(params, pk)
    keyb, symbolsb = Dec(params, sk, ctxt)

    num_symbol_errors = 0
    for i in range(0,min(len(symbolsa),len(symbolsb))):
        if symbolsa[i] != symbolsb[i]:
            num_symbol_errors += 1

    print "number of symbol errors:", num_symbol_errors, "/", min(len(symbolsa),len(symbolsb))
    print "number of symbols from A:", len(symbolsa)
    print "number of symbols from B:", len(symbolsb)

    if keya == keyb and keya != []:
        print "success!"
        print "keya:", sum([GF_to_int(keya[i]) * 2^(rs.F.degree()*i) for i in range(0,len(keya))])
        print "keyb:", sum([GF_to_int(keyb[i]) * 2^(rs.F.degree()*i) for i in range(0,len(keyb))])
    else:
        print "fail!"
        print "len(keya) = ", len(keya), "versus len(keyb) = ", len(keyb)
        print "keya:", sum([GF_to_int(keya[i]) * 2^(rs.F.degree()*i) for i in range(0,len(keya))])
        print "keyb:", sum([GF_to_int(keyb[i]) * 2^(rs.F.degree()*i) for i in range(0,len(keyb))])


