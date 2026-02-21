# SETTINGS
import threading

from Crypto.Cipher import PKCS1_OAEP

messager_port=55555

# PROGRAM
import flask
from flask import Flask
import socket
import requests
from Crypto.PublicKey import RSA

class User():
    def __init__(self, name,priv_key=None, pub_key=None,ip=""):
        self.ip=ip
        self.name = name
        self.pub_key = pub_key
        self.priv_key = priv_key

    def json(self):
        return {"name":self.name,"ip":self.ip,}

app = Flask(__name__)

def get_my_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
    finally:
        s.close()
    return ip

def scan_to_users():
    ip_range = ".".join(get_my_ip().split(".")[:-1]) + "."
    for i in range(1, 255):
        ip = ip_range + str(i)
        try:
            threading.Thread(target=send_handshake, args=(ip,),daemon=True).start()
        except Exception:
            pass

def send_handshake(ip):
    try:
        okay = requests.post(f"{ip}:{messager_port}/ping").json()["ok"]
        if okay:
            priv_key = RSA.generate(2048)
            pub_key = priv_key.public_key()
            json_handshake=requests.post(f"{ip}:{messager_port}/handshake",json=session.json()|{"pub_key":pub_key.exportKey()}).json()
            users.append(User(json_handshake["name"],priv_key,pub_key,ip))
            print(f"Hello, {json_handshake['name']}!")

    except:
        return False

def send_message(text,user):
    cipher_rsa = PKCS1_OAEP.new(user.pub_key)
    ciphertext = cipher_rsa.encrypt(text).hex()


@app.route("/ping")
def ping():return flask.jsonify({"ok":True,"name":session.name})

@app.route("/handshake")
def handshake():
    json_request=flask.request.json
    for user in users:
        if user.name == json_request["name"] and user.ip == json_request["ip"]:
            users.remove(user)
    users.append(User(json_request["name"],None,RSA.import_key(json_request["pub_key"]),json_request["ip"]))
    return flask.jsonify({})

if __name__ == "__main__":
    session = User("test",ip=get_my_ip())
    users=[]
    scan_to_users()
    app.run("0.0.0.0", port=messager_port)
