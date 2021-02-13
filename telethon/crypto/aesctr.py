"""
This module holds the AESModeCTR wrapper class.
"""
import pyaes

try:
    import tgcrypto
except ImportError:
    tgcrypto = None


class AESModeCTR:
    """Wrapper around pyaes.AESModeOfOperationCTR mode with custom IV"""
    # TODO Maybe make a pull request to pyaes to support iv on CTR

    def __init__(self, key, iv):
        """
        Initializes the AES CTR mode with the given key/iv pair.

        :param key: the key to be used as bytes.
        :param iv: the bytes initialization vector. Must have a length of 16.
        """
        # TODO Use libssl if available
        assert isinstance(key, bytes)
        self._aes = pyaes.AESModeOfOperationCTR(key)

        assert isinstance(iv, bytes)
        assert len(iv) == 16
        self._aes._counter._counter = list(iv)
        self.key = key
        self.iv = iv

    def encrypt(self, data):
        """
        Encrypts the given plain text through AES CTR.

        :param data: the plain text to be encrypted.
        :return: the encrypted cipher text.
        """
        if tgcrypto:
            return tgcrypto.ctr256_encrypt(data, self.key, self.iv, bytearray(1))
        return self._aes.encrypt(data)

    def decrypt(self, data):
        """
        Decrypts the given cipher text through AES CTR

        :param data: the cipher text to be decrypted.
        :return: the decrypted plain text.
        """
        if tgcrypto:
            return tgcrypto.ctr256_decrypt(data, self.key, self.iv, bytearray(1))
        return self._aes.decrypt(data)
