# run me:
# sage parameters.sage

from numpy import mean, std
from scipy.stats import norm

def SampleSparseInteger( modulus_bitsize, mass ):
    integer = 0
    for i in range(0, mass):
        integer += 1 << (Integers(modulus_bitsize).random_element())
    return integer

class Parameters:
    def __init__( self, modulus_bitsize, security_level, bch_codeword_length, bch_errors_corrigible, rs_codeword_length, rs_errors_corrigible ):
        self.modulus_bitsize = modulus_bitsize
        self.security_level = security_level
        
        self.additive_mass = None
        self.multiplicative_mass = None
        self.bit_errors_mean = None
        self.bit_errors_std = None

        self.bch_codeword_length = bch_codeword_length
        self.bch_corrigible_errors = bch_errors_corrigible

        self.rs_codeword_length = rs_codeword_length
        self.rs_corrigible_errors = rs_errors_corrigible

    def ComputeMasses( self ):
        if self.additive_mass == None or self.multiplicative_mass == None:
            for self.multiplicative_mass in range(0, self.modulus_bitsize // 2):
                if log(1.0*binomial(self.modulus_bitsize, self.multiplicative_mass), 2.0) >= self.security_level:
                    break
            self.additive_mass = self.security_level - self.multiplicative_mass

    def ComputeStatistics( self, num_trials ):
        p = 2^self.modulus_bitsize - 1
        bit_errors_list = []
        byte_errors_list = []
        for i in range(0, num_trials):
            g = ZZ(Integers(2^self.modulus_bitsize).random_element())
            am = SampleSparseInteger(self.modulus_bitsize, self.multiplicative_mass)
            aa = SampleSparseInteger(self.modulus_bitsize, self.additive_mass)
            bm = SampleSparseInteger(self.modulus_bitsize, self.multiplicative_mass)
            ba = SampleSparseInteger(self.modulus_bitsize, self.additive_mass)

            ga = ((am*g + aa)*bm) % p
            gb = ((bm*g + ba)*am) % p

            stra = bin(ga)[2:]
            strb = bin(gb)[2:]
            while len(stra) < len(strb):
                stra = '0' + stra
            while len(strb) < len(stra):
                strb = '0' + strb

            num_errors = 0
            for j in range(0, self.bch_codeword_length):
                if stra[j+8] != strb[j+8]:
                    num_errors += 1

            bit_errors_list.append(num_errors)

            stra = hex(ga)
            strb = hex(gb)
            while len(stra) != max(len(stra), len(strb)) or len(stra)%2 != 0:
                stra = '0' + stra
            while len(strb) != max(len(stra), len(strb)) or len(strb)%2 != 0:
                strb = '0' + strb

            num_errors = 0
            for j in range(0, self.rs_codeword_length/8):
                if stra[(2*j+2):(2*j+4)] != strb[(2*j+2):(2*j+4)]:
                    num_errors += 1

            byte_errors_list.append(num_errors)

        self.bit_errors_mean = mean(bit_errors_list)
        self.bit_errors_std = std(bit_errors_list, ddof=1)

        self.byte_errors_mean = mean(byte_errors_list)
        self.byte_errors_std = std(byte_errors_list, ddof=1)

    def OptimalRSCodewordNumber( self ):
        if self.byte_errors_mean == None or self.byte_errors_std == None:
            print "compute statistics first"
            return 0

        failure_probability = 1.0 - norm.cdf(1.0*(self.rs_corrigible_errors - self.byte_errors_mean) / self.byte_errors_std)
        #print "failure probability for one codeword: %f " % failure_probability, "with t =", self.rs_corrigible_errors, ", mu =", self.byte_errors_mean, "and sigma =", self.byte_errors_std

        all_fail_probability = 1.0
        number = 0
        for number in range(0, floor(self.modulus_bitsize / self.rs_codeword_length)+10):
            if all_fail_probability <= 2^-60: #<= 10^(-17):
                break
            all_fail_probability *= failure_probability

        if number * self.rs_codeword_length > self.modulus_bitsize:
            #print "need too many codewords"
            return 0

        return number

    def OptimalBCHCodewordNumber( self ):
        if self.bit_errors_mean == None or self.bit_errors_std == None:
            print "compute statistics first"
            return 0

        failure_probability = 1.0 - norm.cdf(1.0*(self.bch_corrigible_errors - self.bit_errors_mean) / self.bit_errors_std)
        #print "failure probability for one codeword: %f " % failure_probability, "with t =", self.bch_corrigible_errors, ", mu =", self.bit_errors_mean, "and sigma =", self.bit_errors_std

        all_fail_probability = 1.0
        number = 0
        for number in range(0, floor(self.modulus_bitsize / self.bch_codeword_length)+10):
            if all_fail_probability <= 2^-60: #<= 10^(-17):
                break
            all_fail_probability *= failure_probability

        if number * self.bch_codeword_length > self.modulus_bitsize:
            #print "need too many codewords"
            return 0

        return number

mersenne_primes = [44497, 86243, 110503, 132049, 216091]
security_levels = [128, 192, 256]
delta = 321
bch_codeword_length = 255*8#delta*12 + 256
bch_corrigible_errors = 160#(delta-1)/2
rs_codeword_length = 255*8
rs_corrigible_errors = 110

for p in mersenne_primes:
    for seclvl in security_levels:
        params = Parameters(p, seclvl, bch_codeword_length, bch_corrigible_errors, rs_codeword_length, rs_corrigible_errors)
        params.ComputeMasses()
        params.ComputeStatistics(1000)

        pubkey_size = seclvl + p

        print "RS:",
        repetitions = params.OptimalRSCodewordNumber()
        ciphertext_size = p + repetitions*rs_codeword_length + seclvl
        print "p = 2^%i-1, sclvl = %i ---> xmass = %i, +mass = %i, mean = %f, std = %f, #codewords = %i, |ctxt| = %f kB, |pk| = %f kB" % (p, seclvl, params.multiplicative_mass, params.additive_mass, params.byte_errors_mean, params.byte_errors_std, repetitions, (1.0*ciphertext_size)/8/1024, 1.0*pubkey_size/8/1024)

        print "BCH:",
        repetitions = params.OptimalBCHCodewordNumber()
        ciphertext_size = p + repetitions*bch_codeword_length + seclvl
        print "p = 2^%i-1, sclvl = %i ---> xmass = %i, +mass = %i, mean = %f, std = %f, #codewords = %i, |ctxt| = %f kB, |pk| = %f kB" % (p, seclvl, params.multiplicative_mass, params.additive_mass, params.bit_errors_mean, params.bit_errors_std, repetitions, (1.0*ciphertext_size)/8/1024, 1.0*pubkey_size/8/1024)

    print ""

