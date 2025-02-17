# encryption.py

import base64
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from config import Config

BLOCK_SIZE = 16

def aes_encrypt(plaintext: str) -> str:
    """
    Encrypts plaintext using AES (CBC) with the key from Config.AES_KEY.
    Returns base64-encoded cipher text.
    """
    cipher = AES.new(Config.AES_KEY, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(plaintext.encode('utf-8'), BLOCK_SIZE))
    return base64.b64encode(cipher.iv + ct_bytes).decode('utf-8')

def aes_decrypt(encrypted_b64: str) -> str:
    """
    Decrypts a base64-encoded AES cipher text.
    Returns the plaintext string.
    """
    raw = base64.b64decode(encrypted_b64)
    iv = raw[:BLOCK_SIZE]
    ct = raw[BLOCK_SIZE:]
    cipher = AES.new(Config.AES_KEY, AES.MODE_CBC, iv)
    pt = unpad(cipher.decrypt(ct), BLOCK_SIZE)
    return pt.decode('utf-8')
