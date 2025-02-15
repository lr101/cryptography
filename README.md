# Cryptography with Python

This project implements encryption and decryption using RSA for exchanging a symmetric key and uses it to encrypt and decrypt a message using AES. 
As only dependency numpy is used for easier matrix operations in AES.

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
  docker container run ghcr.io/lr101/cryptography/crypto:latest
 ```