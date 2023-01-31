from Crypto.Cipher import DES3
from Crypto.Util.Padding import pad, unpad
import json
from base64 import b64encode, b64decode

class DesChipper:
    encryption_key = ""
    encryption_iv = ""

    def __init__(self, key:str, iv:str):
        self.encryption_key = key
        self.encryption_iv = iv

    def encrypt(self, message: str):
        cipher = DES3.new(self.encryption_key.encode(), DES3.MODE_OFB)
        cipher_text = cipher.encrypt(pad(message.encode(), DES3.block_size))
        iv = b64encode(cipher.iv).decode('utf-8')
        ct = b64encode(cipher_text).decode('utf-8')
        result = json.dumps({'iv': iv, 'ciphertext': ct})
        return result

    def decrypt(self, message):
        try:
            cipher = DES3.new(self.encryption_key.encode(), DES3.MODE_OFB, b64decode(self.encryption_iv))
            pt = unpad(cipher.decrypt(b64decode(message)), DES3.block_size)
            return pt.decode()
        except(ValueError, KeyError) as e:
            print(e)
            print("Incorrect decryption")

