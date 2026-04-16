import threading
import traceback

from utils.cryptographer import *
import requests
import notifications

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
    def __init__(self,port,ip,session,user_list,on_new_func=None,whitelist=[]):
        self.port = port
        self.ip = ip
        self.session=session
        self.user_list=user_list
        self.on_new_func=on_new_func
        self.cryptographer=Cryptographer()
        self.whitelist = whitelist
    def send_handshake(self,ip):
        try:
            if len([i for i in self.whitelist if i.replace(" ", "") != "" and (len(i) == 0 or i[0] != "#")]) > 0:
                if not ip in [i for i in self.whitelist if i.replace(" ", "") != "" and (len(i) == 0 or i[0] != "#")]:
                    return {"okay": False}
            if ip == self.ip: return False
            print(ip)
            if not ":" in ip:
                url = f"http://{ip}:{self.port}/ping"
            else:
                url = f"http://{ip}/ping"
            print(url)
            okay = requests.post(url).json()["ok"]
            print(okay)
            if okay:
                try:
                    print(ip)
                    keys = self.cryptographer.generate_keys()
                    aes_key = keys["aes_key"]
                    priv_key = keys["priv_key"]
                    pub_key = keys["pub_key"]
                    if not ":" in ip:
                        url=f"http://{ip}:{self.port}/handshake"
                    else:
                        url = f"http://{ip}/handshake"
                    json_handshake = requests.post(url, json=self.session.json() | {
                        "pub_key": pub_key.exportKey().hex(),"aes_key": aes_key.hex()}).json()
                    user = User(json_handshake["name"], priv_key, RSA.import_key(bytes.fromhex(json_handshake["pub_key"])), ip,aes_key)
                    if json_handshake.get("bot_port")!=None:
                        user.bot=True
                        user.port=json_handshake.get("bot_port")
                    if UsernameValidator().check_username(json_handshake["name"]):
                        self.on_new_func(user)
                        return True
                    else:
                        return False
                except Exception as e:
                     return False
        except Exception as e:
            return False

    def new_user_handler(self,func):
        self.on_new_func = func
        return func

class MessageSend():
    def __init__(self,port,ip,cryptographer,server):
        self.port = port
        self.server=server
        self.cryptographer=cryptographer
        self.on_get_func = None

    def send_message(self,message,target):
        cipher_text = self.cryptographer.encode_rsa(target.pub_key, message.text)
        for d in message.documents:
            self.server.files[d.rnd_key] = d
        if not target.bot:
            requests.post(f"http://{target.ip}:{self.port}/message", json={"message": cipher_text,"documents": [d.rnd_key for d in message.documents]})
        else:
            answer = requests.post(f"http://{target.ip}/message",
                          json={"message": cipher_text},timeout=10).json()
            decrypted_text = self.cryptographer.decode_rsa(target.priv_key, answer["message"])

            self.on_get_func(decrypted_text, target, [])


class DocumentInstaller():
    def __init__(self, port,cryptographer):
        self.port = port
        self.cryptographer = cryptographer
    def install(self,document,user):
        try:
            response = requests.get(f"http://{user.ip}:{self.port}/document/{document}").content
            with open(document,"wb") as f:
                f.write(self.cryptographer.decode_aes(response,user.aes_key))
            notifications.Notification("Успех", f"{document} успешно установлен", onclick=lambda e: 0 + 0).view()
        except:
            notifications.Notification("Ошибка",f"Ошибка в установке документа {document}",onclick=lambda e:0+0).view()