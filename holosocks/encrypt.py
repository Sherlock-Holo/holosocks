try:
    from Cryptodome.Cipher import AES
    from Cryptodome.Hash import SHA256
    from Cryptodome.Random import get_random_bytes
except ImportError:
    from Crypto.Cipher import AES
    from Crypto.Hash import SHA256
    from Crypto.Random import get_random_bytes


class aes_cfb:
    def __init__(self, key, iv=None):
        '''Create a new AES-CFB cipher.

        iv: a 16 bytes length byte string, if not provided a random iv is used
        key: Your password like: passw0rd'''

        self.key = SHA256.new(key.encode()).digest()
        if not iv:
            self._iv = get_random_bytes(AES.block_size)

        else:
            if len(iv) != 16:
                error_msg = 'iv length should be 16, not {}'
                raise ValueError(error_msg.format(len(iv)))

            elif type(iv) != bytes:
                raise TypeError('iv should be byte')

            else:
                self._iv = iv

        self.cipher = AES.new(self.key, AES.MODE_CFB, self._iv)

    def encrypt(self, data):
        '''Return cipher'''
        return self.cipher.encrypt(data)

    def decrypt(self, data):
        '''Return plain text'''
        return self.cipher.decrypt(data)

    @property
    def iv(self):
        return self._iv


if __name__ == '__main__':
    # AES-CFB
    print('AES-256-CFB')
    en = aes_cfb('test')
    iv = en.iv
    cipher = en.encrypt(b'holo')
    de = aes_cfb('test', iv)
    print(de.decrypt(cipher))
