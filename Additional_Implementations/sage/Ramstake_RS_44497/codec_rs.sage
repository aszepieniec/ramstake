load("reedsolomon.sage")
from CompactFIPS202 import SHA3_256

class CODEC:
    def __init__( self, k, n, inner_n, reps ):
        self.k = k
        self.n = n
        self.rs_codec = ReedSolomon(8, 224)
        self.repetitions = floor(1.0*self.n/(self.rs_codec.n*8))

        if reps > 0 and reps < self.repetitions:
            self.repetitions = reps
        self.n = 255 * self.repetitions * 8

    def encode( self, buf ):
        return bytearray(list(self.rs_codec.EncodeBytes(buf)) * self.repetitions)

    def decode( self, buf, helper ):
        for i in range(0, self.repetitions):
            decoded = self.rs_codec.DecodeBytes(buf[(255*i):(255*(i+1))])
            if SHA3_256(decoded) == helper:
                return decoded

        # if we get here, then we failed
        return bytearray([0]*self.k)

