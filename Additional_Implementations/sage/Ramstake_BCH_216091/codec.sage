class CODEC:
    def __init__( self, k, n ):
        self.k = k
        self.n = n
        self.inner_codec = ReedSolomon(8, 224)
        self.repetitions = 1.0*self.n/self.inner_codec.n

    def encode( self, buf ):
        return self.inner_codec.EncodeBytesMultiple(buf)

    def decode( self, buf ):
        return self.inner_codec.DecodeBytesMultiple(buf)

