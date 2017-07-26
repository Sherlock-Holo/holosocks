from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto import Random


class aes_cfb:
    def __init__(self, key):
        self.key = SHA256.new(key.encode()).digest()

    def new(self, iv=None):
        if not iv:
            self.iv = Random.new().read(AES.block_size)

        else:
            if len(iv) != 16:
                raise ValueError('iv length should be 16 but given value length {}'.format(len(iv)))

            elif type(iv) != bytes:
                raise TypeError('iv should be bytes')

            else:
                self.iv = iv

        self.cipher = AES.new(self.key, AES.MODE_CFB, self.iv)

    def encrypt(self, data):
        return self.cipher.encrypt(data)

    def decrypt(self, data):
        return self.cipher.decrypt(data)
