load("reedsolomon.sage")
from csprng import csprng
from binascii import hexlify

RAMSTAKE_SEED_LENGTH = 32
RAMSTAKE_KEY_LENGTH = 32
RAMSTAKE_MODULUS_BITSIZE = 16352
RAMSTAKE_SEEDENC_LENGTH = 1020
RAMSTAKE_SECRET_BITSIZE = 12264
RAMSTAKE_SECRET_SPARSITY = 23

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

    print "got g."

    return g

def ramstake_keygen( random_seed, kat ):
    rng = csprng()
    rng.seed(random_seed)

    if kat == 1:
        print "# ramstake_keygen"
        print "seed: ", hexlify(random_seed)

    print "getting p ..."

    p = 2^RAMSTAKE_MODULUS_BITSIZE
    if RAMSTAKE_MODULUS_BITSIZE == 16352:
        p -= 28169
    elif RAMSTAKE_MODULUS_BITSIZE == 22040:
        p -= 2325

    print "got p; getting g"

    seed = rng.generate(RAMSTAKE_SEED_LENGTH)
    print "got seed for g"
    g = ramstake_generate_g(seed)
    if kat == 1:
        print "seed for generating g:", hexlify(seed)
        print "g:", g

    return 0, 1

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


