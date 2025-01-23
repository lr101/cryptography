from rsa import RSA
from aes import AES
from aes import AESMode
from aes import KeyLength
from aes import generate_symmetric_key as generate

RSA_PRIME_SIZE_BITS = 128

def main(aes_key_length: KeyLength, aes_mode: AESMode, message: str):
    rsa = RSA(RSA_PRIME_SIZE_BITS)
    sym_key, sym_key_str = generate(aes_key_length.key_length)
    aes = AES(key=sym_key, strength=aes_key_length, mode=aes_mode)

    plaintext_rsa = rsa.encrypt(sym_key_str)
    ciphertext_rsa = rsa.decrypt(plaintext_rsa)

    print(f"RSA: Encrypted symmetric key: {plaintext_rsa}")
    print(f"RSA: Decrypted Symmetric key: {sym_key_str}")
    print(f"RDA: Decrypted symmetric key: {ciphertext_rsa}")
    if sym_key_str == ciphertext_rsa:
        print("RSA: Symmetric key is successfully decrypted!")
        ciphertext_aes = aes.encrypt("")
        print(f"AES: Encrypted message: {ciphertext_aes}")
        plaintext_aes = aes.decrypt(ciphertext_aes)
        print(f"AES: Decrypted message: {plaintext_aes}")
        if message == plaintext_aes:
            print("AES: Message is successfully decrypted!")



# Example usage:
if __name__ == "__main__":
    main(aes_key_length=KeyLength.AES128, aes_mode=AESMode.CBC, message="Hi")

