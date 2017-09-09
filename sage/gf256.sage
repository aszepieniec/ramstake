F = FiniteField(2^8, "z", modulus='primitive')
z = F.gen()
Fx = PolynomialRing(F, "x")
x = Fx.gen()

def gf_hex( element ):
    if element == 1:
        return '01'
    char = 0
    coeffs = element.polynomial().coefficients(sparse=False)
    string = ''
    for i in range(0, len(coeffs)):
        if coeffs[i] == 1:
            char += 2^i
    if char < 16:
        string += '0'
    string += hex(char)
    return string

def hex_gf( byte ):
    bits = bin(int(byte, 16))[2:]
    elm = F(0)
    for i in range(0, len(bits)):
        elm *= z
        if bits[i] == '1':
            elm += 1
    return elm

def gfx_hex( poly ):
    coeffs = poly.coefficients(sparse=False)
    string = ''
    for i in range(0, len(coeffs)):
        string += gf_hex(coeffs[i])
    return string

def hex_gfx( string ):
    poly = Fx(0)
    i = 0
    degree = len(string)/2
    while i < len(string):
        poly += hex_gf(string[i:(i+2)]) * x^(i/2)
        i = i + 2
    return poly

def dlog( i ):
    if i == 0:
        return 255
    a = F(1)
    for j in range(0, 256):
        if gf_hex(a) == hex(i) or gf_hex(a) == '0'+hex(i) or gf_hex(a) == hex(i)[2:] or gf_hex(a) == '0'+hex(i)[2:]:
            return j
        a = a * z
    print z, " is not a generator"
    return -1

def antilog( e ):
    return int(gf_hex(z^e), 16)

def log_table( ):
    print "unsigned char gf256_dlogs[256] = {",
    for i in range(0,256):
        if i % 8 == 0:
            print ""
        print "0x%x" % dlog(i),
        if i != 255:
            print ", ",
    print "\n};"

def antilog_table( ):
    print "unsigned char gf256_antilogs[256] = {",
    for i in range(0,256):
        if i % 8 == 0:
            print ""
        print "0x%x" % antilog(i),
        if i != 255:
            print ", ",
    print "\n};"
