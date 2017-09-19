import sys
load("ramstake.sage")
from csprng import csprng

def test( seed ):

    rng = csprng()
    rng.seed(seed)

    print "randomness:", rng.generate_ulong()


if len(sys.argv) != 2 or len(sys.argv[1]) % 2 != 0:
    print "usage: sage test d13d13deadbeef"
else:
    test(bytearray(sys.argv[1].decode('hex')))

