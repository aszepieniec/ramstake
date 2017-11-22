load("bch.sage")

class CODEC:
    def __init__( self, k, n ):
        self.k = k
        self.n = n
        self.bch_codec = BCH(12, 223, floor((223*6+256)/8)*8)
        self.repetitions = floor(1.0*self.n/self.bch_codec.n)

    ##
    # encode
    # Encode a message as a sequence of self.repetitions BCH codewords.
    # @params:
    #  * buf : list of ceil(self.k/8) bytes representing the message.
    #    If self.k is not divisible by 8, then the least significant
    #    bits of the last byte are used.
    def encode( self, buf ):
        # cast to list of GF(2) field elements
        felms = [self.bch_codec.F(0)]*len(buf)*8
        for i in range(0, len(buf)):
            for j in range(0, 8):
                if (int(buf[i]) >> j) % 2 != 0:
                    felms[i*8+j] = self.bch_codec.F(1)

        cdwd = self.bch_codec.Encode(felms)
        # bunch together back into bytes
        bytes_cdwd = [sum(2^j for j in range(0,8) if cdwd[8*i+j] == self.bch_codec.F(1)) for i in range(0, len(cdwd)/8)]

        return bytearray(bytes_cdwd * self.repetitions)

    ##
    # hamming_distance
    # Compute the Hamming distance between two strings of bits.
    def hamming_distance( self, str1, str2 ):
        dist = (max(len(str1), len(str2)) - min(len(str1), len(str2)))*8
        if len(str1) != len(str2):
            print "lengths of strings is not the same!!"
            print hexlify(str1)
            print hexlify(str2)
        for i in range(0, min(len(str1), len(str2))):
            if str1[i] != str2[i]:
                for j in range(0, 8):
                    if ((str1[i] ^^ str2[i]) >> j) % 2 == 1:
                        dist += 1
        return dist

    ##
    # decode
    # Decode a repetition-BCH code.
    # @params:
    #  * buf : list of self.repetitions * (self.n / 8) bytes
    #    representing the repetition codeword. If self.n is
    #    not divisible by 8, then the least significant bits
    #    of the last byte are used.
    # * helper : the hash of the message, if available
    def decode( self, buf, helper=False ):
        # decode each codeword separately and then take a majority vote
        msgs = dict()
        cdwds = dict()
        for i in range(0, self.repetitions):
            # grab codeword
            cdwd = buf[i*ceil(self.bch_codec.n/8) : ((i+1)*ceil(self.bch_codec.n/8))]

            # maybe we have already decoded a similar codeword?
            # if so, increase that counter and skip the rest of this iteration
            candidate = False
            for (k,v) in cdwds.iteritems():
                dist = self.hamming_distance(v, cdwd)
                if dist <= (self.bch_codec.delta-1)/2:
                    candidate = True
                    msgs[k] += 1
                    #print "%i. skipping decoding because decoding will give" % i, hexlify(bytearray(k)), "anyway (hamming weight: %i)" % dist
                    break
                #else:
                    #print "%i. distance is too large:" % i, dist
            if candidate == True:
                continue

            # turn codeword into list of bits (move me down later)
            rcvd = [self.bch_codec.F(0)] * self.bch_codec.n
            for j in range(0, len(cdwd)):
                for k in range(0, 8):
                    if (int(cdwd[j]) >> k) % 2 == 1:
                        rcvd[j*8 + k] = self.bch_codec.F(1)

            # decode
            msg = tuple(self.bch_codec.Decode(rcvd))
            msg_bytes = bytearray([sum(2^j for j in range(0,8) if list(msg)[l*8+j] == self.bch_codec.F(1)) for l in range(0, ceil(256/8))])

            # if we have helper data, use it
            if helper != False and SHA3_256(msg_bytes) == helper:
                return msg_bytes

            # add to dicts (if necessary) or increase counter
            if msg_bytes != bytearray([0]*len(msg_bytes)):
                if tuple(msg_bytes) in msgs:
                    msgs[tuple(msg_bytes)] += 1
                else:
                    recoded = self.bch_codec.Encode(msg)
                    rec = bytearray([sum(2^j for j in range(0,8) if list(recoded)[l*8+j] == self.bch_codec.F(1)) for l in range(0, ceil(len(recoded)/8))])
                    if self.hamming_distance(rec, cdwd) < (self.bch_codec.delta-1)/2:
                        print "%i. adding to dict:" % i, hexlify(msg_bytes)
                        msgs[tuple(msg_bytes)] = 1
                        cdwds[tuple(msg_bytes)] = rec

        if len(msgs) == 0:
            return [0] * ceil(self.k/8)
        # else,
        maxvotes = max(msgs.itervalues())
        maxmsgs = [k for (k, v) in msgs.iteritems() if v == maxvotes]
        # if len(maxmsgs) > 1:
        #   do something intelligent (?)
        return bytearray(maxmsgs[0])

