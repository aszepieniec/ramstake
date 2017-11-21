class BCH:
    def __init__( self, m, delta, n ):
        self.delta = delta
        p = 2
        self.m = m
        self.n = n

        if m == 16:
            IF = FiniteField(256, "a")
            a = IF.gen()
            IFZ = PolynomialRing(IF, "Z")
            Z = IFZ.gen()
            modulus = a^5+a^3+a^2+1 + Z + Z^2
            self.E = QuotientRing(IFZ, modulus)
            self.z = self.E.gen()
        else:
            self.E = FiniteField(p^m, "z")
            self.z = self.E.gen()
        self.Ex = PolynomialRing(self.E, "X")
        self.X = self.Ex.gen()
        self.F = FiniteField(2)
        self.Fx = PolynomialRing(self.F, "x")
        self.x = self.Fx.gen()


        # get compatible polynomial ring
        self.Ex = PolynomialRing(self.E, "x")
        self.X = self.Ex.gen()

        # get generator
        self.generator = self.Fx(1)
        minpolys = []
        for i in range(1,delta):
            temp = self.z^i
            minpoly = self.MinPoly(self.z^i)
            self.generator = lcm(self.generator, minpoly)
            minpolys.append(minpoly)

        # collapse list
        listsize = len(minpolys)
        while listsize != 1:
            j = 0
            i = 0
            while i < listsize - 1:
                minpolys[j] = lcm(minpolys[i], minpolys[i+1])
                i = i + 2
                j = j + 1
            if i == listsize - 1:
                minpolys[j] = minpolys[i]
                j = j + 1
            listsize = j

        self.k = self.n - self.generator.degree()
        self.t = floor((delta-1)/2)

    def Coefficients( self, elm ):
        if self.m != 16:
            coeffs = elm.coefficients(sparse=False)
            while len(coeffs) != self.m:
                coeffs.append(0)
            return coeffs

        coeffs = elm.lift().coefficients(sparse=False)
        clist = [0] * 16
        for i in range(0, len(coeffs)):
            ccoeffs = coeffs[i].polynomial().coefficients(sparse=False)
            for j in range(0, len(ccoeffs)):
                clist[i*8+j] = ccoeffs[j]
        return clist

    def MinPoly( self, elm, verbose=False ):
        if self.m != 16:
            return elm.minpoly()

        mat = copy(MatrixSpace(self.F, 16, 17).zero())
        acc = elm.parent()(1)
        for i in range(0, 17):
            mat[:,i] = matrix(self.Coefficients(acc)).transpose()
            acc = acc * elm

        if verbose == True:
            print "matrix:"
            print mat

        K = mat.right_kernel().matrix()
        K = K[:, ::-1].echelon_form()
        K = K[:, ::-1]

        poly = self.Fx(0)
        for i in range(0, K.ncols()):
            poly += K[K.nrows()-1, i] * self.x^i

        return poly

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

    def InterruptedEuclid( self, S, g ):
        #print "inside interrupted euclidean procedure ..."
        t1 = self.Ex(1)
        t2 = self.Ex(0)
        #print "S:", self.gf65536x2str(S)
        #print "g:", self.gf65536x2str(g)
        r1 = g
        r2 = S
        s1 = self.Ex(0)
        s2 = self.Ex(1)
        while r2.degree() >= t2.degree():
            #print "r1:", self.gf65536x2str(r1)
            #print "r2:", self.gf65536x2str(r2)
            #print "t1:", self.gf65536x2str(t1)
            #print "t2:", self.gf65536x2str(t2)
            #print "s1:", self.gf65536x2str(s1)
            #print "s2:", self.gf65536x2str(s2)
            quo = r1 // r2
            #print "quotient:", self.gf65536x2str(quo)
            #print "remainder:", self.gf65536x2str(r1 - r2*quo)
            #sys.stdin.read(1)
            
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
            ev = self.E(0)
            zi = self.z^(i)
            for j in range(0,min(self.n,len(word))):
                ev += self.E(word[j]) * zi^j
            s[i-1] = ev

        return s

    def DecodeSyndrome( self, syndrome ):
        s = self.Ex(0)
        for i in range(0,len(syndrome)):
            s += syndrome[i] * self.X^(i)

        g = self.X^(self.delta)

        # get sigma and omega
        # ... from interrupted Euclid
        sigma, omega = self.InterruptedEuclid(s, g)

        # get derivative of sigma
        #sigma_deriv = self.Ex(0)
        #for i in range(1,sigma.degree()+1):
        #    sigma_deriv += sigma.coefficients(sparse=False)[i] * i * self.X^(i-1)

        # correct errors
        errors = [self.F(0)] * self.n
        num_errors = 0
        for i in range(0, self.n):
            if sigma(self.z^(-i)) == 0:
                errors[i] = self.F(1)
            #    errors[i] = omega(self.z^-i)/ sigma_deriv(self.z^-i)

        return errors

    def DecodeErrorFree( self, codeword ):
        poly = self.Fx(0)
        for i in range(0, len(codeword)):
            poly += self.F(codeword[i]) * self.x^i
        quo = poly // self.generator
        coeffs = [self.F(0) for i in range(0, self.k)]
        for i in range(0, quo.degree()+1):
            coeffs[i] = quo.coefficients(sparse=False)[i]
        return coeffs

    def gf655362str( self, e ):
        coeffs = self.Coefficients(e)
        integer = 0
        for i in range(0, len(coeffs)):
            integer += 2^i * ZZ(coeffs[i])
        h = hex(integer)
        while len(h) != 4:
            h = '0' + h
        return h

    def gf65536x2str( self, p ):
        return ''.join(self.gf655362str(c) for c in p.coefficients(sparse=False))

    def Decode( self, received ):
        #poly = self.Ex(0)
        #for i in range(0,len(received)):
        #    poly += received[i] * self.x^i
        s = self.Syndrome(received)
        if s == [self.E(0)] * len(s):
            return self.DecodeErrorFree(received)
        e = self.DecodeSyndrome(s)
        corrected = [received[i] + e[i] for i in range(0, self.n)]
        return self.DecodeErrorFree(corrected)

