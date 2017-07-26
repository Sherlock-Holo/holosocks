from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto import Random
import base64


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
                raise TypeError('iv should be bytes not {}'.format(type(iv)))

            else:
                self.iv = iv

        self.cipher = AES.new(self.key, AES.MODE_CFB, self.iv)

    def encrypt(self, data):
        return self.cipher.encrypt(data)

    def decrypt(self, data):
        return self.cipher.decrypt(data)


if __name__ == '__main__':
    aes_256_cfb = aes_cfb('test')
    aes_256_cfb.new()
    cipher = aes_256_cfb.encrypt(b'sherlock holo')
    print('cipher len:', len(cipher[16:]))
    print('cipher:', cipher)
    plain_text = aes_256_cfb.decrypt(cipher)
    print('plain text len:', len(plain_text))
    print('plain text:', plain_text)
    print('iv:', aes_256_cfb.iv)
