import platform
import socket
import string
from Crypto.Cipher import AES
#from scapy.all import ARP, Ether, srp
from Crypto.Util.Padding import pad, unpad
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
import hashlib
from Crypto.Random import get_random_bytes

def get_my_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
    finally:
        s.close()
    return ip


class Singleton(type):
    _instances = {}
    def __call__(cls, *args, **kwargs):
        if cls not in cls._instances:
            cls._instances[cls] = super().__call__(*args, **kwargs)
        return cls._instances[cls]

class Cryptographer():
    def generate_keys(self):
        priv_key = RSA.generate(2048)
        pub_key = priv_key.public_key()
        aes_key=get_random_bytes(32)
        return {"priv_key": priv_key, "pub_key": pub_key, "aes_key": aes_key}
    def encode_rsa(self, pub_key, text):
        cipher_rsa = PKCS1_OAEP.new(pub_key)
        cipher_text = cipher_rsa.encrypt(text.encode()).hex()
        return cipher_text
    def decode_rsa(self, priv_key, cipher_text):
        cipher_text=bytes.fromhex(cipher_text)
        decrypt_rsa = PKCS1_OAEP.new(priv_key)
        decrypted_text = decrypt_rsa.decrypt(cipher_text).decode()
        return decrypted_text
    def encode_aes(self, raw, key):
        iv = get_random_bytes(AES.block_size)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        encrypted_data = cipher.encrypt(pad(raw, AES.block_size))
        return iv + encrypted_data
    def decode_aes(self, raw, key):
        iv = raw[:AES.block_size]
        encrypted_payload = raw[AES.block_size:]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        return unpad(cipher.decrypt(encrypted_payload), AES.block_size)

class UsernameValidator():
    def __init__(self):
        self.similar_letters={"eng":"ABEKMHOPCTXaeopcxy","rus":"АВЕКМНОРСТХаеорсху"}
        self.whitelist = string.ascii_letters+string.digits+string.punctuation+ ("".join([i for i in "АБВГДЕЁЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯабвгдеёжзийклмнопрстуфхцчшщъыьэюя" if i not in self.similar_letters["rus"]]))+" "
    def validate_username(self,username):
        username = "".join([i if i in self.whitelist else "" if i not in self.similar_letters["rus"] else self.similar_letters["eng"][self.similar_letters["rus"].index(i)] for i in username])[:16].strip()
        if username=="":
            return "Incorrect_username"
        return username
    def check_username(self,username):
        return len(username.strip()) == len(self.validate_username(username))

class FingerPrint(metaclass=Singleton):
    def __init__(self):
        self.fingerprint = hashlib.sha256(f"{platform.system()}{platform.platform()}{platform.processor()}{platform.architecture()}{platform.version()}".encode()).hexdigest()

class MITMChecker():
    def get_mac_addresses(self,ip_range):
        # arp_request = ARP(pdst=ip_range)
        # broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
        # packet = broadcast / arp_request
        # answered_list = srp(packet, timeout=2, verbose=False)[0]
        # devices = []
        # for sent, received in answered_list:
        #     devices.append(received.hwsrc)
        # return devices
        return []
    def check(self):
        return False
        # found_devices = self.get_mac_addresses(".".join(get_my_ip().split('.')[:-1]) + ".0/24")
        # for i in found_devices:
        #     if found_devices.count(i)>1:
        #         return True
        # return False

