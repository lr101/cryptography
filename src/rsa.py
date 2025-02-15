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
def generate_large_prime(bits:int=1024) -> int:
    while True:
        n = random.getrandbits(bits) | 1  # Ensure n is odd
        a = random.randint(2, n - 2)
        if miller_rabin_test(n, a):
            return n


def calculate_phi(prime_q: int, prime_p: int) -> int:
    return (prime_p - 1) * (prime_q - 1)

def calculate_n(prime_q: int, prime_p: int) -> int:
    return prime_p * prime_q

def calculate_e(phi: int) -> int:
    for e in range(2, phi):
        if math.gcd(e, phi) == 1:
            return e
    raise ValueError("Unable to find e such that gcd(e, phi) = 1")

def extended_gcd(a: int, b: int) -> tuple[int, int, int]:
    if a == 0:
        return b, 0, 1
    gcd, x1, y1 = extended_gcd(b % a, a)
    s = y1 - (b // a) * x1
    t = x1
    return gcd, s, t

def mod_inverse(e: int, phi: int) -> int:
    gcd, s, _ = extended_gcd(e, phi)
    if gcd != 1:
        return -1
    return s % phi

# Encrypt message using public key (e, n)
def encrypt(m: int, e: int, n: int) -> int:
    return pow(m, e, n)

# Decrypt message using private key (d, n)
def decrypt(c: int, d: int, n: int) -> int:
    return pow(c, d, n)

class RSAReceiver:
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

    def decrypt(self, encrypted_message: int) -> str:
        message_int = decrypt(encrypted_message, self._private_key, self.public_devisor)
        return message_int.to_bytes((message_int.bit_length() +  7) // 8, 'big').decode('utf-8')

class RSASender:
    def __init__(self, public_key: int, public_devisor: int, key_size: int):
        self.public_key = public_key
        self.public_devisor = public_devisor
        self._key_size = key_size

    def encrypt(self, message: str) -> int:
        assert len(message) < self._key_size
        message_int = int.from_bytes(message.encode('utf-8'), 'big')
        return encrypt(message_int, self.public_key, self.public_devisor)