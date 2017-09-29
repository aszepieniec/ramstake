import sys
load("ramstake.sage")
from csprng import csprng

def test( num_trials, seed ):


    rng = csprng()
    rng.seed(seed)
    print "randomness byte:", hexlify(rng.generate(1))
    print "randomness:", rng.generate_ulong()

    print "num trials:", num_trials

    if num_trials == 1:
        kat = 2
    else:
        kat = 0
    num_successes = 0
    num_integrity_failures = 0
    num_decoding_failures = 0
    for trial_index in range(0, num_trials):
        sk, pk = ramstake_keygen(rng.generate(RAMSTAKE_SEED_LENGTH), kat)
        sk_bytes = ramstake_export_secret_key(sk)
        #print "serialization of secret key:", hexlify(sk_bytes)

        c, k1 = ramstake_encaps(rng.generate(RAMSTAKE_SEED_LENGTH), pk, kat)
        val = ramstake_decaps(c, sk, kat)

        if type(val) != type(1):
            k2 = val
            num_successes += 1
        elif val == -1:
            num_decoding_failures += 1
        elif val == -2:
            num_integrity_failures += 1

    print "Ran", num_trials, "trials with", num_successes, "successes and", (num_integrity_failures + num_decoding_failures), "failures."
    print "Failures:"
    print " *", num_decoding_failures, "decoding errors"
    print " *", num_integrity_failures, "integrity errors"
    print "Successes:"
    print " *", num_successes, "total successes"

if len(sys.argv) != 3 or len(sys.argv[2]) % 2 != 0:
    print "usage: sage test [num trials, eg 13] [random seed in hex, eg d13d13deadbeef]"
else:
    arg2 = bytearray(sys.argv[2].decode('hex'))
    test(int(sys.argv[1]), bytearray(arg2))

