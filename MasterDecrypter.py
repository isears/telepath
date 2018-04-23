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
        self.key_size = int(cipher_size / 8)
        self.IV_size = 4  # TODO: This changes based on cipher mode (e.g., GCM, CBC, etc.)
        self.nonce_size = 8  # TODO: Only relevant in GCM mode, but is this constant for all GCM configurations?
        self.mac_size = 16  # TODO: is this guaranteed to always be the same across all cipher suites?

    class _OrderedKeyMaterial:
        def __init__(self):
            self.client_write_MAC_key = b''
            self.server_write_MAC_key = b''
            self.client_write_key = b''
            self.server_write_key = b''
            self.client_write_IV = b''
            self.server_write_IV = b''

    def decrypt_client(self, ciphertext):
        key_material = self._PRF(self.master_secret, b'key expansion', self.server_random + self.client_random)
        ordered_keys = self._get_keys(key_material)
        nonce = ciphertext[:self.nonce_size]
        mac = ciphertext[-1 * self.mac_size:]
        ciphertext = ciphertext[self.nonce_size:-1 * self.mac_size]

        aes_decrypter = AES.new(ordered_keys.client_write_key, self.cipher_mode, ordered_keys.client_write_IV + nonce)
        return aes_decrypter.decrypt(ciphertext)

    def decrypt_server(self, ciphertext):  # TODO: This is sad and broken (can't decrypt data from server)
        key_material = self._PRF(self.master_secret, b'key expansion', self.server_random + self.client_random)
        ordered_keys = self._get_keys(key_material)
        nonce = ciphertext[:self.nonce_size]
        mac = ciphertext[-1 * self.mac_size]
        ciphertext = ciphertext[self.nonce_size:-1 * self.mac_size]

        aes_decrypter = AES.new(ordered_keys.server_write_key, self.cipher_mode, ordered_keys.server_write_IV + nonce)
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

    def _get_keys(self, key_material):  # TODO: General cleanup and make this work for more than just GCM mode
        ret = self._OrderedKeyMaterial()
        ret.client_write_MAC_key = b''
        ret.server_write_MAC_key = b''

        ret.client_write_key = key_material[0:self.key_size]
        ret.server_write_key = key_material[self.key_size: 2 * self.key_size]
        ret.client_write_IV = key_material[2 * self.key_size: 2 * self.key_size + self.IV_size]
        ret.server_write_IV = key_material[2 * self.key_size + self.IV_size:2 * self.key_size + 2 * self.IV_size]

        return ret