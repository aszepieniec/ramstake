class ReedSolomon:
    def __init__( self, m, delta ):
        self.delta = delta
        p = 2
        self.m = m
        self.n = p^m - 1
        self.F = FiniteField(p^m, "z")
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
                errors[i] = omega(self.z^-i)/ sigma_deriv(self.z^-i)

        return errors

    def DecodeErrorFree( self, codeword ):
        poly = self.Fx(0)
        for i in range(0, len(codeword)):
            poly += codeword[i] * self.x^i
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

