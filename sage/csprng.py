from CompactFIPS202 import KeccakF1600
import binascii

class csprng:
    def __init__( self ):
        self.state_size = 200
        self.seed_rate = 32
        self.gen_rate = 32
        self.state = bytearray([0 for i in range(self.state_size)])
    
    def seed( self, seed ):
        # absorb full input blocks
        for i in range(0, len(seed) // self.seed_rate):
            for j in range(0, self.seed_rate):
                self.state[j] ^= seed[i*self.seed_rate + j]
            self.state = KeccakF1600(self.state)

        # absorb remainder of the last input block
        for j in range(0, len(seed) % self.seed_rate):
            self.state[j] ^= seed[(len(seed)//self.seed_rate)*self.seed_rate + j]
        self.state = KeccakF1600(self.state)

    def generate( self, length ):
        output = bytearray([0 for i in range(0, length)])

        # squeeze out full output blocks
        for i in range(0, length // self.gen_rate):
            for j in range(0, self.gen_rate):
                output[i*self.gen_rate + j] = self.state[j]
            self.state = KeccakF1600(self.state)

        # squeeze out remaining output blocks
        for j in range(0, length % self.gen_rate):
            output[(length//self.gen_rate)*self.gen_rate + j] = self.state[j]
        self.state = KeccakF1600(self.state)

        return output

