# Cryptography with Python

Keywords:
- Cryptography
- Python
- Affine Cipher
- Double Block Cipher
- RSA
- AES
- CBC mode

## Description

The first part includes encryption and decryption using affine and double block ciphers.
And the second part implements encryption and decryption using RSA for exchanging a symmetric key and uses it to encrypt and decrypt a message using AES in either ECB or CBC mode.

When running the main function, a cli is provided to navigate the different options. 
Specifically for the second part this is supposed to simulate a real life communication between two users.

Explanation of the different options in the RSA/AES cli:

- **Option (1):** First generate the RSA key (1) by specifying the key size in bits in the given menu.
- **Option (2):** Encrypt and decrypt a message (2) using RSA. **The message should be less than the key size.**
  - **Sub option (1):** Make sure to this sub option **at least once** to generate AES symmetric keys before moving on to the AES encryption. This creates a 128-bit key, encrypts it and decrypts it using RSA to simulate the key exchange.
  - **Sub option (2):** Encrypt and decrypt custom messages.
  - **Sub option (3):** Encrypt and decrypt a file content.
- **Option (3):** Encrypt and decrypt a message using AES.
  - **Sub option (1):** Encrypt and decrypt a message using AES. A random IV is generated and *transmitted* to the other user using ECB mode. Then the message is encrypted & decrypted using AES in CBC mode to simulate the real life communication between two users.
  - **Sub option (2):** Encrypt and decrypt a file content using AES. Same concept as above.
- **Option (4):** Exit

## How to run

### Local

This is the preferred way to run this project!

1. Have python installed
2. Install dependencies: `pip install -r requirements.txt`
3. Run `python main.py`

### Docker

This option should only be used if something goes wrong with the local run for reproducible results!

Run docker container
 ```shell
  $ docker run -it --rm ghcr.io/lr101/cryptography/crypto:latest /bin/bash
  $ python main.py
 ```