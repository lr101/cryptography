import random
import math


"""
Perform Miller-Rabin primality test with base a.
"""
def miller_rabin_test(n, a):

    if n < 2:
        return False
    if n in (2, 3):
        return True
    if n % 2 == 0:
        return False

    # Find m and k such that n - 1 = m * 2^k
    # As long as m is even, we keep dividing it by 2.
    # Each division by 2 increases k by 1.
    k, m = 0, n - 1
    while m % 2 == 0:
        m //= 2
        k += 1

    # Compute T1 = a^m mod n
    t = pow(a, m, n)
    if t == 1 or t == n - 1:
        return True

    for _ in range(k - 1):
        t = pow(t, 2, n)
        if t == n - 1:
            return True
        if t == 1:
            return False

    return False

"""
Generate a large prime number of specified bit length using Miller-Rabin test.
"""
def generate_large_prime(bits=1024):
    while True:
        n = random.getrandbits(bits) | 1  # Ensure n is odd
        a = random.randint(2, n - 2)
        if miller_rabin_test(n, a):
            return n


def calculate_phi(prime_q, prime_p):
    return (prime_p - 1) * (prime_q - 1)

def calculate_n(prime_q, prime_p):
    return prime_p * prime_q

def calculate_e(phi):
    for e in range(2, phi):
        if math.gcd(e, phi) == 1:
            return e

def extended_gcd(a, b):
    if a == 0:
        return b, 0, 1
    gcd, x1, y1 = extended_gcd(b % a, a)
    s = y1 - (b // a) * x1
    t = x1
    return gcd, s, t

def mod_inverse(e, phi):
    gcd, s, _ = extended_gcd(e, phi)
    if gcd != 1:
        return -1
    return s % phi

# Encrypt message using public key (e, n)
def encrypt(m, e, n):
    return pow(m, e, n)

# Decrypt message using private key (d, n)
def decrypt(c, d, n):
    return pow(c, d, n)

class RSA:
    def __init__(self, key_size: int):
        prime_q = generate_large_prime(key_size)
        prime_p = generate_large_prime(key_size)
        print("RSA: Generated PrimeQ:", prime_q)
        print("RSA: Generated PrimeP:", prime_p)
        phi = calculate_phi(prime_q, prime_p)
        n = calculate_n(prime_q, prime_p)
        print("RSA: Calculated phi:", phi, "n:", n)
        e = calculate_e(phi)
        d = mod_inverse(e, phi)
        print(f"RSA: Public key (e, phi): ({e}, {n})")
        print(f"RSA: Private key (d, phi): ({d}, {n})")
        self.public_key = e
        self._private_key = d
        self.public_devisor = n

    def encrypt(self, message):
        return encrypt(message, self.public_key, self.public_devisor)

    def decrypt(self, encrypted_message):
        return decrypt(encrypted_message, self._private_key, self.public_devisor)
