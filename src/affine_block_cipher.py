import numpy as np

from sympy import mod_inverse

# Affine Cipher Class
class AffineCipher:
    def __init__(self, a, b):
        if np.gcd(a, 26) != 1:
            raise ValueError("'a' must be coprime with 26.")
        self.a = a
        self.b = b
        self.a_inv = mod_inverse(a, 26)  # Compute modular inverse for decryption

    def encrypt(self, plaintext):
        ciphertext = ''
        for char in plaintext:
            if char.isalpha():
                offset = ord('A') if char.isupper() else ord('a')
                cipher_char = chr(((self.a * (ord(char) - offset) + self.b) % 26) + offset)
                ciphertext += cipher_char
            else:
                ciphertext += char
        return ciphertext

    def decrypt(self, ciphertext):
        plaintext = ''
        for char in ciphertext:
            if char.isalpha():
                offset = ord('A') if char.isupper() else ord('a')
                plain_char = chr(((self.a_inv * ((ord(char) - offset - self.b) % 26)) % 26) + offset)
                plaintext += plain_char
            else:
                plaintext += char
        return plaintext

# Columnar Transposition Encryption
def columnar_transposition_encrypt(plaintext, key):
    key_order = sorted(range(len(key)), key=lambda x: key[x])
    num_cols = len(key)
    num_rows = int(np.ceil(len(plaintext) / num_cols))
    grid = [['' for _ in range(num_cols)] for _ in range(num_rows)]
    idx = 0
    for i in range(num_rows):
        for j in range(num_cols):
            if idx < len(plaintext):
                grid[i][j] = plaintext[idx]
                idx += 1
    ciphertext = ''
    for col in key_order:
        for row in range(num_rows):
            if grid[row][col]:
                ciphertext += grid[row][col]
    return ciphertext

# Columnar Transposition Decryption
def columnar_transposition_decrypt(ciphertext, key):
    key_order = sorted(range(len(key)), key=lambda x: key[x])
    num_cols = len(key)
    num_rows = int(np.ceil(len(ciphertext) / num_cols))
    grid = [['' for _ in range(num_cols)] for _ in range(num_rows)]
    idx = 0
    for col in key_order:
        for row in range(num_rows):
            if idx < len(ciphertext):
                grid[row][col] = ciphertext[idx]
                idx += 1
    plaintext = ''
    for row in range(num_rows):
        for col in range(num_cols):
            plaintext += grid[row][col]
    return plaintext.strip()

# Product Cipher Encryption
def product_cipher_encrypt(plaintext, affine_a, affine_b, key1, key2):
    affine = AffineCipher(affine_a, affine_b)
    step1 = affine.encrypt(plaintext)
    step2 = columnar_transposition_encrypt(step1, key1)
    final_ciphertext = columnar_transposition_encrypt(step2, key2)
    return final_ciphertext

# Product Cipher Decryption
def product_cipher_decrypt(ciphertext, affine_a, affine_b, key1, key2):
    affine = AffineCipher(affine_a, affine_b)
    step1 = columnar_transposition_decrypt(ciphertext, key2)
    step2 = columnar_transposition_decrypt(step1, key1)
    final_plaintext = affine.decrypt(step2)
    return final_plaintext

