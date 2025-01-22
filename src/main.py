import random
import math

from rsa import RSA

PRIME_SIZE = 16

def main():
    rsa = RSA(PRIME_SIZE)

    symmetric_key = random.getrandbits(PRIME_SIZE)
    encrypted_symmetric_key = rsa.encrypt(symmetric_key)
    decrypted_symmetric_key = rsa.decrypt(encrypted_symmetric_key)

    print(f"Encrypted symmetric key: {encrypted_symmetric_key}")
    print(f"Symmetric key: {symmetric_key}")
    print(f"Decrypted symmetric key: {decrypted_symmetric_key}")
    if symmetric_key == decrypted_symmetric_key:
        print("Symmetric key is successfully decrypted!")



# Example usage:
if __name__ == "__main__":
    main()

