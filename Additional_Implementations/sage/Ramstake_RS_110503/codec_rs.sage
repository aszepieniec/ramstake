load("reedsolomon.sage")

class CODEC:
    def __init__( self, k, maxn, innern, reps ):
        self.k = k
        self.n = maxn
        self.rs_codec = ReedSolomon(8, 224)
        self.repetitions = floor(1.0*self.n/(self.rs_codec.n*8))
        if reps > 0 and reps < self.repetitions:
            self.repetitions = reps
        self.n = 255 * self.repetitions * 8

    def encode( self, buf ):
        return self.rs_codec.EncodeBytesMultiple(buf, self.repetitions)

    def decode( self, buf, helper=False ):
        return self.rs_codec.DecodeBytesMultiple(buf, self.repetitions, helper)

