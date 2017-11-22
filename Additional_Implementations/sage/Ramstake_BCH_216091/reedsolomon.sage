class ReedSolomon:
    def __init__( self, m, delta ):
        self.delta = delta
        p = 2
        self.m = m
        self.n = p^m - 1
        self.F = FiniteField(p^m, "z", "conway")
        self.z = self.F.gen()

        # get compatible polynomial ring
        self.Fx = PolynomialRing(self.F, "x")
        self.x = self.Fx.gen()

        # get generator
        self.generator = self.Fx(1)
        for i in range(1,delta):
            self.generator = self.generator * (self.x - self.z^i)

        self.k = self.n - self.generator.degree()
        self.t = floor((delta-1)/2)

    def Encode( self, msg ):
        if len(msg) > self.k:
            print "will only accept words of length <= k =", self.k, "for encoding"
        
        # convert word to polynomial
        poly = self.Fx(0)
        for i in range(0, min(self.k, len(msg))):
            poly += msg[i] * self.x^i

        # multiply with generator
        codeword = poly * self.generator

        # extract coefficients
        coeffs = codeword.coefficients(sparse=False)
        while len(coeffs) != self.n:
            coeffs.append(0)

        return coeffs

    def CastField( self, byte ):
        acc = self.F(0)
        for i in range(0, 8):
            if byte & (2^i) != 0:
                acc += self.z^(i)
        return acc

    def CastByte( self, field ):
        if field == 0:
            return 0
        coeffs = field.polynomial().coefficients(sparse=False)
        acc = 0
        for i in range(0, len(coeffs)):
            acc += ZZ(coeffs[i]) * 2^(i)
        return acc

    def EncodeBytes( self, msg ):
        msg_ = [self.CastField(m) for m in msg]
        cdwd = self.Encode(msg_)
        return bytearray([self.CastByte(c) for c in cdwd])

    def EncodeBytesMultiple( self, msg, multiplicity ):
        return bytearray(list(self.EncodeBytes(msg)) * multiplicity)# got to love python one-liners

    def Reduce( self, L ):
        while True:
            quo = L[1,0] // L[0,0]
            if quo != 0:
                L[1,:] = L[1,:] - quo * L[0,:]
            elif max(L[1,0].degree(), L[1,1].degree()) < max(L[0,0].degree(), L[0,1].degree()):
                L = matrix([[0, 1], [1, 0]]) * L
            else:
                return L

    def InterruptedEuclid( self, S, g ):
        t1 = self.Fx(1)
        t2 = self.Fx(0)
        r1 = g
        r2 = S
        s1 = self.Fx(0)
        s2 = self.Fx(1)
        while r2.degree() >= t2.degree():
            quo = r1 // r2
            
            temp = t1
            t1 = t2
            t2 = temp - quo * t1

            temp = s1
            s1 = s2
            s2 = temp - quo * s1

            temp = r1
            r1 = r2
            r2 = temp - quo * r1

        return (s1, r1)

    def Syndrome( self, word ):
        s = [0]*(self.delta-1)
        for i in range(1, self.delta):
            ev = self.F(0)
            zi = self.z^(i)
            for j in range(0,min(self.n,len(word))):
                ev += word[j] * zi^j
            s[i-1] = ev

        return s

    def DecodeSyndrome( self, syndrome ):
        s = self.Fx(0)
        for i in range(0,len(syndrome)):
            s += syndrome[i] * self.x^(i)

        g = self.x^(self.delta-1)

        # get sigma and omega
        # ... from interrupted Euclid
        sigma, omega = self.InterruptedEuclid(s, g)

        # get derivative of sigma
        sigma_deriv = self.Fx(0)
        for i in range(1,sigma.degree()+1):
            sigma_deriv += sigma.coefficients(sparse=False)[i] * i * self.x^(i-1)

        # correct errors
        errors = [self.F(0)] * self.n
        num_errors = 0
        for i in range(0, self.n):
            if sigma(self.z^-i) == self.F(0):
                num_errors += 1
                errors[i] = omega(self.z^-i)/ sigma_deriv(self.z^-i)

        if num_errors > (self.delta-1)/2:
            return [0] * self.n

        return errors

    def DecodeErrorFree( self, codeword ):
        poly = self.Fx(0)
        for i in range(0, len(codeword)):
            poly += codeword[i] * self.x^i
        rem = poly % self.generator
        if rem != 0:
            return [self.F(0)] * self.k
        quo = poly // self.generator
        coeffs = [self.F(0) for i in range(0, self.k)]
        for i in range(0, quo.degree()+1):
            coeffs[i] = quo.coefficients(sparse=False)[i]
        return coeffs

    def Decode( self, received ):
        poly = self.Fx(0)
        for i in range(0,len(received)):
            poly += received[i] * self.x^i
        s = self.Syndrome(received)
        if s == [self.F(0)] * len(s):
            return self.DecodeErrorFree(received)
        e = self.DecodeSyndrome(s)
        corrected = [received[i] + e[i] for i in range(0, self.n)]
        return self.DecodeErrorFree(corrected)

    def DecodeBytes( self, received ):
        rec_ = [self.CastField(r) for r in received]
        word = self.Decode(rec_)
        return [self.CastByte(w) for w in word]

    def HW( self, byte ):
        return (byte & 1)  + ((byte >> 1) & 1) + ((byte >> 2) & 1) + ((byte >> 3) & 1) + ((byte >> 4) & 1) + ((byte >> 5) & 1) + ((byte >> 6) & 1) + ((byte >> 7) & 1)

    def DecodeBytesMultiple( self, received, multiplicity, helper=False ):
        # if we have helper info, use it
        if helper != False:
            for i in range(0, multiplicity):
                decoded = self.DecodeBytes(received[(self.n*i):(self.n*(i+1))])
                if SHA3_256(decoded) == helper:
                    return decoded

        # decode each chunk
        decoded = [self.DecodeBytes(received[(self.n*i):(self.n*(i+1))]) for i in range(0, multiplicity)]

        # determine error counts
        num_errors = [-1]*multiplicity
        for i in range(0, multiplicity):
            stream = self.EncodeBytesMultiple(decoded[i], multiplicity)
            for j in range(0, len(stream)):
                stream[j] = stream[j] ^^ received[j]
                num_errors[i] += self.HW(stream[j])

        # determine winner
        have_winner = False
        winner = 0
        for i in range(0, multiplicity):
            if have_winner == False and num_errors[i] != -1:
                have_winner = True
                winner = i
            elif have_winner == True and num_errors[i] < num_errors[winner]:
                winner = i

        # return winner data
        return decoded[winner]

