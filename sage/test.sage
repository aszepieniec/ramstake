import sys
load("ramstake.sage")
from csprng import csprng

def test( seed ):

    rng = csprng()
    rng.seed(seed)

    print "randomness:", rng.generate_ulong()

    sk, pk = ramstake_keygen(rng.generate(RAMSTAKE_SEED_LENGTH), 0)
    sk_bytes = ramstake_export_secret_key(sk)
    #print "serialization of secret key:", hexlify(sk_bytes)

    c, k1 = ramstake_encaps(rng.generate(RAMSTAKE_SEED_LENGTH), pk, 0)
    k2 = ramstake_decaps(c, sk, 0)

    if k1 == k2:
        print "success! k1 == k2 \o/"
    else:
        print "k1:", hexlify(k1)
        print "k2:", hexlify(k2)

if len(sys.argv) != 2 or len(sys.argv[1]) % 2 != 0:
    print "usage: sage test d13d13deadbeef"
else:
    test(bytearray(sys.argv[1].decode('hex')))

