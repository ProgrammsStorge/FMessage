import threading
from utils.cryptographer import *
import requests


from user import *

class Scaner():
    def __init__(self,port,ip,handshaker):
        self.port = port
        self.ip = ip
        self.handshaker=handshaker

    def scan(self):
        ip_range = ".".join(self.ip.split(".")[:-1]) + "."
        print(ip_range)
        for i in range(1, 255):
            ip = ip_range + str(i)
            try:
                threading.Thread(target=self.handshaker.send_handshake, args=(ip,), daemon=True).start()
            except Exception as e:
                print(e)

class Handshaker():
    def __init__(self,port,ip,session,user_list,on_new_func=None):
        self.port = port
        self.ip = ip
        self.session=session
        self.user_list=user_list
        self.on_new_func=on_new_func
    def send_handshake(self,ip):
        try:
            if ip == self.ip: return False
            #print(ip)
            okay = requests.post(f"http://{ip}:{self.port}/ping").json()["ok"]
            #print(okay)
            if okay:
                try:
                    keys = self.cryptographer.generate_keys()
                    priv_key = keys["priv_key"]
                    pub_key = keys["pub_key"]
                    json_handshake = requests.post(f"http://{ip}:{self.port}/handshake", json=self.session.json() | {
                        "pub_key": pub_key.exportKey().decode()}).json()
                    user = User(json_handshake["name"], priv_key, RSA.import_key(json_handshake["pub_key"]), ip)
                    self.user_list.append(user)

                    self.on_new_func(user)
                except Exception as e:
                    return False
        except Exception as e:
            #print(e)
            return False

    def new_user_handler(self,func):
        self.on_new_func = func
        return func

class MessageSend():
    def __init__(self,port,ip,cryptographer):
        self.port = port
        self.cryptographer=cryptographer
    def send_message(self,message,target):
        print(message.text,target.ip,target.name)
        cipher_text = self.cryptographer.encode(target.pub_key,message.text)
        requests.post(f"http://{target.ip}:{self.port}/message", json={"message": cipher_text})

