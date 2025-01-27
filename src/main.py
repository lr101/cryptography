from rsa import RSAReceiver, RSASender
from aes import AES
from aes import KeyLength
from aes import generate_symmetric_key as generate

RSA_PRIME_SIZE_BITS = 1028

def main(message: str):
    rsa_receiver = RSAReceiver(RSA_PRIME_SIZE_BITS)
    print(f"---> RSA: Publish public key to sender")
    rsa_sender = RSASender(rsa_receiver.public_key, rsa_receiver.public_devisor)

    sym_key, sym_key_str = generate(KeyLength.AES128.key_length)
    iv_bytes, iv_str = generate(KeyLength.AES128.key_length)
    aes = AES(key=sym_key)

    ciphertext_rsa = rsa_sender.encrypt(sym_key_str + ";" + iv_str)
    print(f"---> RSA: Send encrypted symmetric key to receiver")
    plaintext_rsa = rsa_receiver.decrypt(ciphertext_rsa)
    plaintext_sym_key, plaintext_iv_str = plaintext_rsa.split(";")

    print(f"RSA: Encrypted symmetric key: {ciphertext_rsa}")
    print(f"RSA: Decrypted symmetric key and iv: {plaintext_rsa}")
    if sym_key_str == plaintext_sym_key:
        print("RSA: Symmetric key is successfully decrypted!")
        ciphertext_aes = aes.encrypt(message, plaintext_iv_str)
        print(f"AES: Encrypted message: {ciphertext_aes}")
        print(f"---> AES: Send encrypted message to receiver")
        plaintext_aes = aes.decrypt(ciphertext_aes, plaintext_iv_str)
        print(f"AES: Decrypted message: {plaintext_aes}")
        if message == plaintext_aes:
            print("AES: Message is successfully decrypted!")



# Example usage:
if __name__ == "__main__":
    main(message="REALLY LONG MESSAGE -- come one keep going were at more than 4 blocks already")

