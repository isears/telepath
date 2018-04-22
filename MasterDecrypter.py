from Cryptodome.Cipher import AES
from Cryptodome.Hash import *

MAX_KEY_MATERIAL_LENGTH = 128


class MasterDecrypter:

    def __init__(self, cipher_size, cipher_mode, cipher_hash, master_secret, server_random, client_random):
        self.cipher_size = cipher_size
        self.cipher_mode = cipher_mode
        self.cipher_hash = cipher_hash
        self.master_secret = master_secret
        self.server_random = server_random
        self.client_random = client_random

    class _OrderedKeyMaterial:
        def __init__(self):
            self.client_write_MAC_key = b''
            self.server_write_MAC_key = b''
            self.client_write_key = b''
            self.server_write_key = b''
            self.client_write_IV = b''
            self.server_write_IV = b''

    def decrypt(self, ciphertext):
        key_material = self._PRF(self.master_secret, b'key expansion', self.server_random + self.client_random)
        ordered_keys = self._get_keys(key_material)
        nonce = ciphertext[:8]
        mac = ciphertext[-16:]
        ciphertext = ciphertext[8:-16]

        aes_decrypter = AES.new(ordered_keys.client_write_key, self.cipher_mode, ordered_keys.client_write_IV + nonce)
        return aes_decrypter.decrypt(ciphertext)

    def _HMAC_hash(self, secret, seed):
        return HMAC.new(secret, seed, self.cipher_hash).digest()

    def _P_hash(self, secret, seed):
        res = b''
        A_i = [seed]

        while len(res) < MAX_KEY_MATERIAL_LENGTH:
            A_i.append(self._HMAC_hash(secret, A_i[-1]))  # A_i = HMAC_hash(secret, A_(i-1))

            # P_hash(secret, seed) = HMAC_hash(secret, A(1) + seed) + HMAC_hash(secret, A(2) + seed) + ...
            res += self._HMAC_hash(secret, A_i[-1] + seed)

        return res

    def _PRF(self, secret, label, seed):
        return self._P_hash(secret, label + seed)

    def _get_keys(self, key_material):
        ret = self._OrderedKeyMaterial()
        ret.client_write_MAC_key = b''
        ret.server_write_MAC_key = b''

        ret.client_write_key = key_material[0:32]
        ret.server_write_key = key_material[32:64]
        ret.client_write_IV = key_material[64:68]
        ret.server_write_IV = key_material[68:72]

        return ret