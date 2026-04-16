from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes


class Cryptographer():
    def generate_keys(self):
        priv_key = RSA.generate(2048)
        pub_key = priv_key.public_key()
        aes_key = get_random_bytes(32)
        return {"priv_key": priv_key, "pub_key": pub_key, "aes_key": aes_key}

    def encode(self, pub_key, text):
        cipher_rsa = PKCS1_OAEP.new(pub_key)
        cipher_text = cipher_rsa.encrypt(text.encode()).hex()
        return cipher_text

    def decode(self, priv_key, cipher_text):
        cipher_text = bytes.fromhex(cipher_text)
        decrypt_rsa = PKCS1_OAEP.new(priv_key)
        decrypted_text = decrypt_rsa.decrypt(cipher_text).decode()
        return decrypted_text


