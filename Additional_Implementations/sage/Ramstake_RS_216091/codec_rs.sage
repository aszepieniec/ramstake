load("reedsolomon.sage")

class CODEC:
    def __init__( self, k, n ):
        self.k = k
        self.n = n
        self.rs_codec = ReedSolomon(8, 224)
        self.repetitions = floor(1.0*self.n/(self.rs_codec.n*8))

    def encode( self, buf ):
        return self.rs_codec.EncodeBytesMultiple(buf, self.repetitions)

    def decode( self, buf, helper=False ):
        return self.rs_codec.DecodeBytesMultiple(buf, self.repetitions, helper)

