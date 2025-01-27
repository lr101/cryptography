import base64
import secrets
from enum import Enum

import numpy as np

STATE_SIZE = 4
AES_MESSAGE_BYTES = 16
ROUND_KEY_SIZE = 16

s_box = np.array([
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
])

inv_s_box = np.array([
    0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
    0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
    0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
    0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
    0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
    0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
    0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
    0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
    0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
    0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
    0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
    0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
    0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
    0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
    0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D,
])

def sub_bytes(state):
    for i in range(STATE_SIZE):
        for j in range(STATE_SIZE):
            state[i][j] = s_box[state[i][j]]


def inv_sub_bytes(state):
    for i in range(STATE_SIZE):
        for j in range(STATE_SIZE):
            state[i][j] = inv_s_box[state[i][j]]


def shift_rows(state):
    for i in range(STATE_SIZE):
        state[i] = np.roll(state[i], -i)

def inv_shift_rows(state):
    for i in range(STATE_SIZE):
        state[i] = np.roll(state[i], i)

def mpy(a: np.uint8, b: int) -> np.uint8:
    """
    Perform Galois field multiplication of two bytes.
    """
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= int(a)
        high_bit = a & 0x80
        a <<= 1
        if high_bit:
            a ^= 0x1b  # x^8 + x^4 + x^3 + x + 1
        b >>= 1
    return np.uint8(p % 256)


def mix_columns(state) -> np.ndarray:
    """Mix columns function using galois field multiplication"""
    result = np.zeros((STATE_SIZE, STATE_SIZE), dtype=np.uint8)
    for i in range(STATE_SIZE):
        result[0, i] = mpy(state[0, i],0x02) ^ mpy(state[3, i],0x01) ^ \
                       mpy(state[2, i],0x01) ^ mpy(state[1, i],0x03)
        result[1, i] = mpy(state[1, i],0x02) ^ mpy(state[0, i],0x01) ^ \
                       mpy(state[3, i],0x01) ^ mpy(state[2, i],0x03)
        result[2, i] = mpy(state[2, i],0x02) ^ mpy(state[1, i],0x01) ^ \
                       mpy(state[0, i],0x01) ^ mpy(state[3, i],0x03)
        result[3, i] = mpy(state[3, i],0x02) ^ mpy(state[2, i],0x01) ^ \
                       mpy(state[1, i],0x01) ^ mpy(state[0, i],0x03)
    return result


def inv_mix_columns(state) -> np.ndarray:
    """Inverse mix columns function using galois field multiplication"""
    result = np.zeros((STATE_SIZE, STATE_SIZE), dtype=np.uint8)
    for i in range(STATE_SIZE):
        result[0, i] = mpy(state[0, i],0x0E) ^ mpy(state[3, i],0x09) ^ \
                       mpy(state[2, i],0x0D) ^ mpy(state[1, i],0x0B)
        result[1, i] = mpy(state[1, i],0x0E) ^ mpy(state[0, i],0x09) ^ \
                       mpy(state[3, i],0x0D) ^ mpy(state[2, i],0x0B)
        result[2, i] = mpy(state[2, i],0x0E) ^ mpy(state[1, i],0x09) ^ \
                       mpy(state[0, i],0x0D) ^ mpy(state[3, i],0x0B)
        result[3, i] = mpy(state[3, i],0x0E) ^ mpy(state[2, i],0x09) ^ \
                       mpy(state[1, i],0x0D) ^ mpy(state[0, i],0x0B)
    return result


def add_round_key(state, round_key):
    return state ^ round_key

def generate_symmetric_key(key_size_bytes: int) -> tuple[bytes, str]:
    symmetric_key: bytes = secrets.token_bytes(key_size_bytes)
    symmetric_key_str:str = base64.b64encode(symmetric_key).decode('utf-8')
    return symmetric_key, symmetric_key_str

def aes_encrypt(plaintext: bytes, key: bytes, num_rounds: int) -> bytes:
    """Runs a single block of plaintext through the AES encryption algorithm."""
    state = np.frombuffer(plaintext, dtype=np.uint8).reshape(STATE_SIZE, STATE_SIZE, order='F')
    round_keys = round_key_generator(key, num_rounds)
    state = add_round_key(state, round_keys[0])

    for round_index in range(1, num_rounds):
        sub_bytes(state)
        shift_rows(state)
        state = mix_columns(state)
        state = add_round_key(state, round_keys[round_index])

    sub_bytes(state)
    shift_rows(state)
    state = add_round_key(state, round_keys[-1])

    return state.T.tobytes()

def aes_decryption(ciphertext: bytes, key: bytes, num_rounds: int) -> bytes:
    """Runs a single block of ciphertext through the AES decryption algorithm."""
    state = np.frombuffer(ciphertext, dtype=np.uint8).reshape(STATE_SIZE, STATE_SIZE, order='F')
    round_keys = round_key_generator(key, num_rounds)
    state = add_round_key(state, round_keys[-1])


    for round_index in range(num_rounds - 1, 0, -1):
        inv_shift_rows(state)
        inv_sub_bytes(state)
        state = add_round_key(state, round_keys[round_index])
        state = inv_mix_columns(state)

    inv_shift_rows(state)
    inv_sub_bytes(state)
    state = add_round_key(state, round_keys[0])

    return state.T.tobytes()

def pad(data: bytes) -> bytes:
    """
    Calculate the number of bytes to fill up to modulo AES_MESSAGE_BYTES.
    Fills that many bytes with the value of padding bytes.
    :param data: input data
    :return: padded data
    """
    padding_len = AES_MESSAGE_BYTES - (len(data) % AES_MESSAGE_BYTES)
    padding = bytes([padding_len] * padding_len)
    return data + padding

def remove_padding(data: bytes) -> bytes:
    """
    Remove padding from data by selecting the last byte, which represents the number of padding bytes
    :param data: input data
    :return: unpadded data
    """
    padding_len = data[-1]
    return data[:-padding_len]

def round_key_generator(key: bytes, num_rounds: int) -> list[np.ndarray]:
    """Generates round keys from a given key and number of rounds"""
    result = np.frombuffer(key, dtype=np.uint8)
    for i in range(0, num_rounds):
        wi_previous_row = result[-ROUND_KEY_SIZE:]

        # create the temporary word and generate the next round key when i mod 4 = 0
        wi_temp = np.roll(wi_previous_row[-STATE_SIZE:], -1)
        wi_temp = [s_box[x] for x in wi_temp]
        wi_temp = [wi_temp[0] ^ rcon[i], wi_temp[1], wi_temp[2], wi_temp[3]]
        result = np.append(result, [wi_temp[x] ^ wi_previous_row[:STATE_SIZE][x] for x in range(STATE_SIZE)])

        # create round keys when i mod 4 != 0
        for j in range(STATE_SIZE, ROUND_KEY_SIZE):
            result = np.append(result, wi_previous_row[j] ^ result[-STATE_SIZE])

    # reshape into (4, 4) state format in segments of ROUND_KEY_SIZE
    return [segment.reshape((STATE_SIZE,STATE_SIZE), order='F').astype(np.uint8) for segment in result.reshape(-1, ROUND_KEY_SIZE)]


# round key generator constants
rcon = [
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36,
]

def xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))

class KeyLength(Enum):
    """
    AES key length 16 bytes and 10 rounds
    """
    AES128 = (16, 10)

    def __init__(self, key_length, num_rounds):
        self.key_length = key_length
        self.num_rounds = num_rounds

class AES:
    def __init__(
            self,
            key: bytes,
            strength: KeyLength = KeyLength.AES128):
        assert len(key) == strength.key_length
        self._key: bytes = key
        self._strength = strength

    def encrypt_cbc(self, plaintext: str, iv: str) -> str:
        """
        Encrypt string message using AES in CBC mode
        :param iv: initialization vector with 16 bytes length
        :param plaintext: message as string
        :return: encrypted message bytes as string.hex()
        """
        previous_block = base64.b64decode(iv)
        assert len(previous_block) == AES_MESSAGE_BYTES

        encoded_plaintext: bytes = plaintext.encode('utf-8')
        padded_plaintext: bytes = pad(encoded_plaintext)
        ciphertext: bytes = bytes()

        for i in range(0, len(padded_plaintext), AES_MESSAGE_BYTES):
            block = xor_bytes(padded_plaintext[i:i+AES_MESSAGE_BYTES], previous_block)
            encrypted_block = aes_encrypt(block, self._key, self._strength.num_rounds)
            ciphertext += encrypted_block
            previous_block = encrypted_block
        return ciphertext.hex()

    def encrypt_ecb(self, plaintext: str) -> str:
        """Encrypt message using AES in ECB mode. Should only be used to communicate iv."""
        encoded_plaintext: bytes = plaintext.encode('utf-8')
        padded_plaintext: bytes = pad(encoded_plaintext)
        ciphertext: bytes = bytes()

        for i in range(0, len(padded_plaintext), AES_MESSAGE_BYTES):
            ciphertext += aes_encrypt(padded_plaintext[i:i+AES_MESSAGE_BYTES], self._key, self._strength.num_rounds)
        return ciphertext.hex()

    def decrypt_cbc(self, ciphertext: str, iv: str) -> str:
        """
        Decrypt message using AES in CBC mode
        :param iv: initialization vector with 16 bytes length
        :param ciphertext: message bytes as string
        :return: decrypted message as string
        """
        previous_block = base64.b64decode(iv)
        assert len(previous_block) == AES_MESSAGE_BYTES

        ciphertext_bytes: bytes = bytes.fromhex(ciphertext)
        decrypted_bytes = bytes()

        for i in range(0, len(ciphertext_bytes), AES_MESSAGE_BYTES):
            ciphertext_block = ciphertext_bytes[i:i+AES_MESSAGE_BYTES]
            decrypted_block = aes_decryption(ciphertext_block, self._key, self._strength.num_rounds)
            decrypted_block = xor_bytes(decrypted_block, previous_block)
            decrypted_bytes += decrypted_block
            previous_block = ciphertext_block
        return remove_padding(decrypted_bytes).decode('utf-8')

    def decrypt_ecb(self, ciphertext: str) -> str:
        """Decrypt message using AES in ECB mode. Should only be used to communicate iv."""
        ciphertext_bytes: bytes = bytes.fromhex(ciphertext)
        decrypted_bytes = bytes()

        for i in range(0, len(ciphertext_bytes), AES_MESSAGE_BYTES):
            decrypted_bytes += aes_decryption(ciphertext_bytes[i:i+AES_MESSAGE_BYTES], self._key, self._strength.num_rounds)
        return remove_padding(decrypted_bytes).decode('utf-8')
