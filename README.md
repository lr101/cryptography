# Cryptography with Python

This project implements encryption and decryption using RSA for exchanging a symmetric key and uses it to encrypt and decrypt a message using AES. 
As only dependency numpy is used for easier matrix operations in AES.

## How to run

### Local

1. Have python installed
2. Install dependencies: `pip install -r requirements.txt`
3. Run `python src/main.py`

### Docker
1. Build docker container
    ```shell
     docker build -t crypto .
    ```
2. Run docker container
    ```shell
     docker container run crypto
    ```