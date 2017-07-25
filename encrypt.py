from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto import Random
import base64

class aes_cfb:
    def __init__(self, key):
        self.key = SHA256.new(key.encode()).digest()

    def pkcs7_encode(self, data):
        block_size = 16
        padd_len = block_size - len(data) % block_size
        data += ''.join((chr(i) for i in range(1, padd_len + 1)))
        return data

    def pkcs7_decode(self, data):
        padd_len = data[-1]
        return data[:-padd_len]

    def encrypt(self, data):
        #data = self.pkcs7_encode(data)
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_CFB, iv)
        return base64.b64encode(iv + cipher.encrypt(data))

    def decrypt(self, data):
        data = base64.b64decode(data)
        iv = data[:16]
        data = data[16:]
        cipher = AES.new(self.key, AES.MODE_CFB, iv)
        return cipher.decrypt(data)


if __name__ == '__main__':
    aes_256_cfb = aes_cfb('test')
    cipher = aes_256_cfb.encrypt(b'holo')
    print('cipher:', cipher)
    plain_text = aes_256_cfb.decrypt(cipher)
    print('plain text:', plain_text)
