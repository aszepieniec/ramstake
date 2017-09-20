import sys
load("ramstake.sage")
from csprng import csprng

def test( seed ):

    rng = csprng()
    rng.seed(seed)

    print "randomness:", rng.generate_ulong()

    sk, pk = ramstake_keygen(rng.generate(RAMSTAKE_SEED_LENGTH), 1)
    c, k1 = ramstake_encaps(rng.generate(RAMSTAKE_SEED_LENGTH), pk, 1)
    k2 = ramstake_decaps(c, sk, 1)

if len(sys.argv) != 2 or len(sys.argv[1]) % 2 != 0:
    print "usage: sage test d13d13deadbeef"
else:
    test(bytearray(sys.argv[1].decode('hex')))

