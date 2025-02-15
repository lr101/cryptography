from src.rsa import RSAReceiver, RSASender
from src.aes import AES
from src.aes import KeyLength
from src.aes import generate_symmetric_key as generate

def log_to_file(message: str):
    with open("encryption_log.txt", "a") as log_file:
        log_file.write(message + "\n")

def generate_rsa_keys(key_size: int):
    rsa_receiver = RSAReceiver(key_size)
    log_to_file(f"RSA: Public key: {rsa_receiver.public_key}")
    log_to_file(f"RSA: Public devisor: {rsa_receiver.public_devisor}")
    return rsa_receiver

def random_128bit():
    sym_key, sym_key_str = generate(KeyLength.AES128.key_length)
    log_to_file(f"AES: random base64 128bit string: {sym_key_str}")
    return sym_key, sym_key_str

def encrypt_rsa(rsa_sender, sym_key_str):
    ciphertext_rsa = rsa_sender.encrypt(sym_key_str)
    log_to_file(f"RSA: Encrypted message: {ciphertext_rsa}")
    return ciphertext_rsa

def decrypt_rsa(rsa_receiver, ciphertext_rsa):
    plaintext_rsa = rsa_receiver.decrypt(ciphertext_rsa)
    log_to_file(f"RSA: Decrypted message: {plaintext_rsa}")
    return plaintext_rsa

def encrypt_iv(aes, iv_str):
    ciphertext_iv = aes.encrypt_ecb(iv_str)
    log_to_file(f"AES: Encrypted IV: {ciphertext_iv}")
    return ciphertext_iv

def decrypt_iv(aes, ciphertext_iv):
    plaintext_iv = aes.decrypt_ecb(ciphertext_iv)
    log_to_file(f"AES: Decrypted IV: {plaintext_iv}")
    return plaintext_iv

def encrypt_aes(aes, message, plaintext_iv):
    ciphertext_aes = aes.encrypt_cbc(message, plaintext_iv)
    log_to_file(f"AES: Encrypted message: {ciphertext_aes}")
    return ciphertext_aes

def decrypt_aes(aes, ciphertext_aes, plaintext_iv):
    plaintext_aes = aes.decrypt_cbc(ciphertext_aes, plaintext_iv)
    log_to_file(f"AES: Decrypted message: {plaintext_aes}")
    return plaintext_aes

def open_file():
    file_path = input("-- Enter the path to the file: ")
    try:
        with open(file_path, "r") as file:
            plain_message = file.read()
        return plain_message
    except FileNotFoundError:
        print("\033[91mFile not found.\033[0m")
        return None

def main():
    plain_message = None
    rsa_receiver = None
    rsa_sender = None
    aes = None

    while True:
        try:
            message = input("\nEnter the number of what you would like to do.\n"
                            "(1) Generate RSA keys\n"
                            "(2) Encrypt & decrypt message (or symmetric key) using RSA\n"
                            "(3) Encrypt & decrypt message using AES\n"
                            "(4) Exit\n")

            if message == '1':
                key_size = int(input("-- Enter the key size in bits (example: 1028): "))
                rsa_receiver = generate_rsa_keys(key_size)
                rsa_sender = RSASender(rsa_receiver.public_key, rsa_receiver.public_devisor, key_size)

            elif message == '2':
                if rsa_sender is None:
                    print("\033[91mPlease generate RSA keys first.\033[0m")
                    continue
                choice = input("- Would you like to encrypt a symmetric key (1), a message (2) or a file (3)?")
                if choice == '1':
                    sym_key, sym_key_str = random_128bit()
                    plain_message = sym_key_str
                    aes = AES(key=sym_key)
                elif choice == '2':
                    plain_message = input("-- Enter the message to encrypt: ")
                elif choice == '3':
                    plain_message = open_file()
                    if plain_message is None:
                        continue
                ciphertext_rsa = encrypt_rsa(rsa_sender, plain_message)
                plaintext_rsa = decrypt_rsa(rsa_receiver, ciphertext_rsa)
                print(f"RSA: Encrypted message: {ciphertext_rsa}")
                print(f"RSA: Decrypted message: {plaintext_rsa}")
                if plain_message == plaintext_rsa:
                    print("\033[92mRSA: Messages are equal!\033[0m")
                else:
                    print("\033[91mRSA: Messages are not equal!\033[0m")

            elif message == '3':
                if aes is None:
                    print("\033[91mPlease generate  AES keys first (aka send between clients choice 2 -> 1).\033[0m")
                    continue
                choice = input("- Would you like to encrypt a message (1) or a file (2)?")

                if choice == '1':
                    plain_message = input("-- Enter the message to encrypt: ")
                elif choice == '2':
                    plain_message = open_file()
                    if plain_message is None:
                        continue

                iv_key, iv_key_str = random_128bit()
                ciphertext_iv = encrypt_iv(aes, iv_key_str)
                print(f"AES: Encrypted IV in ECB mode: {ciphertext_iv}")
                plaintext_iv = decrypt_iv(aes, ciphertext_iv)
                print(f"AES: Decrypted IV in ECB mode: {plaintext_iv}")
                ciphertext_aes = encrypt_aes(aes, plain_message, plaintext_iv)
                print(f"AES: Encrypted message in CBC mode: {ciphertext_aes}")
                plaintext_aes = decrypt_aes(aes, ciphertext_aes, plaintext_iv)
                print(f"AES: Decrypted message in CBC mode: {plaintext_aes}")
                if plain_message == plaintext_aes:
                    print("\033[92mAES: Messages are equal!\033[0m")
                else:
                    print("\033[91mAES: Messages are not equal!\033[0m")

            elif message == '4':
                print("Exiting the program.")
                break

            else:
                print("\033[91mInvalid option. Please try again.\033[0m")

        except Exception as e:
            print(f"\033[91mAn error occurred: {e}\033[0m")

# Example usage:
if __name__ == "__main__":
    main()
