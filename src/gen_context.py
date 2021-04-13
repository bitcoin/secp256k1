#!/usr/bin/env python3

import argparse

def modinv(a, n):
    """Compute the modular inverse of a modulo n using the extended Euclidean
    Algorithm. See https://en.wikipedia.org/wiki/Extended_Euclidean_algorithm#Modular_integers.
    """
    # TODO: Change to pow(a, -1, n) available in Python 3.8
    t1, t2 = 0, 1
    r1, r2 = n, a
    while r2 != 0:
        q = r1 // r2
        t1, t2 = t2, t1 - q * t2
        r1, r2 = r2, r1 - q * r2
    if r1 > 1:
        return None
    if t1 < 0:
        t1 += n
    return t1

def modsqrt(a, p):
    """Compute the square root of a modulo p when p % 4 = 3.
    The Tonelli-Shanks algorithm can be used. See https://en.wikipedia.org/wiki/Tonelli-Shanks_algorithm
    Limiting this function to only work for p % 4 = 3 means we don't need to
    iterate through the loop. The highest n such that p - 1 = 2^n Q with Q odd
    is n = 1. Therefore Q = (p-1)/2 and sqrt = a^((Q+1)/2) = a^((p+1)/4)
    secp256k1's is defined over field of size 2**256 - 2**32 - 977, which is 3 mod 4.
    """
    if p % 4 != 3:
        raise NotImplementedError("modsqrt only implemented for p % 4 = 3")
    sqrt = pow(a, (p + 1)//4, p)
    if pow(sqrt, 2, p) == a % p:
        return sqrt
    return None

class EllipticCurve:
    def __init__(self, p, a, b):
        """Initialize elliptic curve y^2 = x^3 + a*x + b over GF(p)."""
        self.p = p
        self.a = a % p
        self.b = b % p

    def affine(self, p1):
        """Convert a Jacobian point tuple p1 to affine form, or None if at infinity.
        An affine point is represented as the Jacobian (x, y, 1)"""
        x1, y1, z1 = p1
        if z1 == 0:
            return None
        inv = modinv(z1, self.p)
        inv_2 = (inv**2) % self.p
        inv_3 = (inv_2 * inv) % self.p
        return ((inv_2 * x1) % self.p, (inv_3 * y1) % self.p, 1)

    def lift_x(self, x):
        """Given an X coordinate on the curve, return a corresponding affine point for which the Y coordinate is even."""
        x_3 = pow(x, 3, self.p)
        v = x_3 + self.a * x + self.b
        y = modsqrt(v, self.p)
        if y is None:
            return None
        return (x, self.p - y if y & 1 else y, 1)

    def double(self, p1):
        """Double a Jacobian tuple p1
        See https://en.wikibooks.org/wiki/Cryptography/Prime_Curve/Jacobian_Coordinates - Point Doubling"""
        x1, y1, z1 = p1
        if z1 == 0:
            return (0, 1, 0)
        y1_2 = (y1**2) % self.p
        y1_4 = (y1_2**2) % self.p
        x1_2 = (x1**2) % self.p
        s = (4*x1*y1_2) % self.p
        m = 3*x1_2
        if self.a:
            m += self.a * pow(z1, 4, self.p)
        m = m % self.p
        x2 = (m**2 - 2*s) % self.p
        y2 = (m*(s - x2) - 8*y1_4) % self.p
        z2 = (2*y1*z1) % self.p
        return (x2, y2, z2)

    def add(self, p1, p2):
        """Add two Jacobian tuples p1 and p2
        See https://en.wikibooks.org/wiki/Cryptography/Prime_Curve/Jacobian_Coordinates - Point Addition"""
        x1, y1, z1 = p1
        x2, y2, z2 = p2
        # Adding the point at infinity is a no-op
        if z1 == 0:
            return p2
        if z2 == 0:
            return p1
        z1_2 = (z1**2) % self.p
        z1_3 = (z1_2 * z1) % self.p
        z2_2 = (z2**2) % self.p
        z2_3 = (z2_2 * z2) % self.p
        u1 = (x1 * z2_2) % self.p
        u2 = (x2 * z1_2) % self.p
        s1 = (y1 * z2_3) % self.p
        s2 = (y2 * z1_3) % self.p
        if u1 == u2:
            if (s1 != s2):
                # p1 and p2 are inverses. Return the point at infinity.
                return (0, 1, 0)
            # p1 == p2. The formulas below fail when the two points are equal.
            return self.double(p1)
        h = u2 - u1
        r = s2 - s1
        h_2 = (h**2) % self.p
        h_3 = (h_2 * h) % self.p
        u1_h_2 = (u1 * h_2) % self.p
        x3 = (r**2 - h_3 - 2*u1_h_2) % self.p
        y3 = (r*(u1_h_2 - x3) - s1*h_3) % self.p
        z3 = (h*z1*z2) % self.p
        return (x3, y3, z3)

    def mul(self, p, n):
        """Compute a point multiplication of Jacobian point p times n."""
        r = (0, 1, 0)
        for i in range(255, -1, -1):
            r = self.double(r)
            if ((n >> i) & 1):
                r = self.add(r, p)
        return r

# The secp256k1 field size
SECP256K1_FIELD_SIZE = 2**256 - 2**32 - 977
# The secp256k1 curve itself
SECP256K1 = EllipticCurve(SECP256K1_FIELD_SIZE, 0, 7)
# The order of the secp256k1 curve
SECP256K1_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
# The standard generator
SECP256K1_G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798, 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8, 1)
# An alternative nothing-up-my-sleeve generator (with unknown DL w.r.t. G; only used for blinding)
SECP256K1_U = SECP256K1.add(SECP256K1.lift_x(int.from_bytes(b"The scalar for this x is unknown", 'big')), SECP256K1_G)

# Parse command-line arguments
parser = argparse.ArgumentParser(description="Generate the precomputed context for libsecp256k1.")
parser.add_argument('--ecmult-gen-precision', '-g', type=int, choices=[2,4,8], default=4, help="Precision bits to tune the precomputed table size for signing. Valid options: 2, 4, 8. The default is 4.")
args = parser.parse_args()

# Derive constants like ecmult_gen.h does
ECMULT_GEN_PREC_B = args.ecmult_gen_precision
ECMULT_GEN_PREC_G = 1 << ECMULT_GEN_PREC_B
ECMULT_GEN_PREC_N = 256 // ECMULT_GEN_PREC_B

# Compute precomputed points and output
print("#ifndef SECP256K1_ECMULT_STATIC_CONTEXT_H")
print("#define SECP256K1_ECMULT_STATIC_CONTEXT_H")
print("#include \"src/group.h\"")
print("#define SC SECP256K1_GE_STORAGE_CONST")
print("#if ECMULT_GEN_PREC_N != %d || ECMULT_GEN_PREC_G != %d" % (ECMULT_GEN_PREC_N, ECMULT_GEN_PREC_G))
print("   #error configuration mismatch, invalid ECMULT_GEN_PREC_N, ECMULT_GEN_PREC_G. Try deleting ecmult_static_context.h before the build.")
print("#endif");
print("static const secp256k1_ge_storage secp256k1_ecmult_static_context[ECMULT_GEN_PREC_N][ECMULT_GEN_PREC_G] = {")
for outer in range(ECMULT_GEN_PREC_N):
    print("{")
    # All but the last bucket use SECP256K1_U * 2^outer as blinding term. The last one uses the negation of the
    # sum of all previous ones (so that they cancel out to 0).
    numsbase = SECP256K1.mul(SECP256K1_U, (1 << outer) if outer + 1 != ECMULT_GEN_PREC_N else (1 - (1 << outer)) % SECP256K1_ORDER)
    for inner in range(ECMULT_GEN_PREC_G):
        point = SECP256K1.affine(SECP256K1.add(SECP256K1.mul(SECP256K1_G, inner << (ECMULT_GEN_PREC_B * outer)), numsbase))
        print("    SC(%uu, %uu, %uu, %uu, %uu, %uu, %uu, %uu, %uu, %uu, %uu, %uu, %uu, %uu, %uu, %uu)%s" % tuple(
            [point[v] >> (32*(7-i)) & 0xFFFFFFFF for v in range(2) for i in range(8)] +
            ["," if inner + 1 != ECMULT_GEN_PREC_G else ""]))
    print("}," if outer + 1 != ECMULT_GEN_PREC_N else "}")
print("};")
print("#undef SC")
print("#endif")
