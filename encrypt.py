from Cryptodome.Cipher import AES
from Cryptodome.Hash import SHA256
from Cryptodome.Random import get_random_bytes


Cipher_Tag = {'aes-256-gcm': 16}
Nonce_Len = 8    # fuck you 12 bytes


class aes_cfb:
    def __init__(self, key):
        self.key = SHA256.new(key.encode()).digest()

    def new(self, iv=None):
        if not iv:
            self.iv = get_random_bytes(AES.block_size)

        else:
            if len(iv) != 16:
                error_msg = 'iv length should be 16 but given value length {}'
                raise ValueError(error_msg.format(len(iv)))

            elif type(iv) != bytes:
                raise TypeError('iv should be bytes')

            else:
                self.iv = iv

        self.cipher = AES.new(self.key, AES.MODE_CFB, self.iv)

    def encrypt(self, data):
        return self.cipher.encrypt(data)

    def decrypt(self, data):
        return self.cipher.decrypt(data)


class aes_gcm:
    def __init__(self, key):
        self.raw_key = key

    def new(self, salt=None, nonce=None):
        if not salt:
            self.salt = get_random_bytes(16)
        else:
            self.salt = salt
        self.key = SHA256.new(self.raw_key + self.salt)

        if not nonce:
            self.nonce = get_random_bytes(Nonce_Len)
        else:
            self.nonce = nonce
        self.cipher = AES.new(self.key, AES.MODE_GCM, self.nonce)

    def encrypt(self, data):
        return self.cipher.encrypt(data), self.cipher.digest()

    def decrypt(self, data, mac):
        plain = self.cipher.decrypt_and_verify(data, mac)
        return plain


if __name__ == '__main__':
    plain = b'holo'
    en = aes_cfb('test')
    en.new()
    cipher = en.encrypt(plain)
    iv = en.iv
    de = aes_cfb('test')
    de.new(iv)
    print(de.decrypt(cipher))
