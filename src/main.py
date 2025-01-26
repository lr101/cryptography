from rsa import RSA
from aes import AES
from aes import AESMode
from aes import KeyLength
from aes import generate_symmetric_key as generate

RSA_PRIME_SIZE_BITS = 128

def main(aes_key_length: KeyLength, aes_mode: AESMode, message: str):
    rsa = RSA(RSA_PRIME_SIZE_BITS)
    # sym_key, sym_key_str = generate(aes_key_length.key_length)
    sym_key_str = "Thats my Kung Fu"
    sym_key = sym_key_str.encode('utf-8')
    aes = AES(key=sym_key, strength=aes_key_length, mode=aes_mode)

    ciphertext_rsa = rsa.encrypt(sym_key_str)
    plaintext_rsa = rsa.decrypt(ciphertext_rsa)

    print(f"RSA: Encrypted symmetric key: {ciphertext_rsa}")
    print(f"RDA: Decrypted symmetric key: {plaintext_rsa}")
    print(f"hex string {sym_key.hex()}")
    if sym_key_str == plaintext_rsa:
        print("RSA: Symmetric key is successfully decrypted!")
        ciphertext_aes = aes.encrypt(message)
        print(f"AES: Encrypted message: {ciphertext_aes}")
        plaintext_aes = aes.decrypt(ciphertext_aes)
        print(f"AES: Decrypted message: {plaintext_aes}")
        if message == plaintext_aes:
            print("AES: Message is successfully decrypted!")



# Example usage:
if __name__ == "__main__":
    main(aes_key_length=KeyLength.AES128, aes_mode=AESMode.CBC, message="Two One Nine Two")

