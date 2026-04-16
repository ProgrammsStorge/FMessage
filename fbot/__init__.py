import flask
from flask import Flask
from .user import *
from .cryptographer import *

class Bot():
    def __init__(self,name,port=50000):
        self.name = name
        self.avatar = ""
        self.on_get_message=None
        self.on_new_user = None
        self.users_list = UserList([])
        self.cryptographer = Cryptographer()
        self.app = Flask(self.name)
        self.port=port

    def new_message_handler(self,func):
        self.on_get_message=func
        return func

    def start(self):
        @self.app.route("/handshake",methods=['POST'])
        def handshake():
            data = flask.request.get_json(force=True)
            return self.handshake(flask.request.remote_addr, data)

        @self.app.route("/ping", methods=['POST'])
        def ping():
            return {"ok": True, "name": self.name}

        @self.app.route("/message", methods=['POST'])
        def message():
            data = flask.request.get_json(force=True)
            return self.get_message(flask.request.remote_addr, data)

        self.app.run(host="0.0.0.0", port=self.port)

    def new_user_handler(self,func):
        self.on_new_user=func
        return func

    def handshake(self,ip,json_request):
        try:
            self.users_list.users = [u for u in self.users_list.users if u.ip != ip]
            keys = self.cryptographer.generate_keys()
            priv_key = keys["priv_key"]
            pub_key = keys["pub_key"]
            user = User(json_request["name"], priv_key, RSA.import_key(bytes.fromhex(json_request["pub_key"])), ip,
                        bytes.fromhex(json_request["aes_key"]))
            self.users_list.append(user)
            self.on_new_user(user)
            return flask.jsonify({"bot_port": self.port,"pub_key": pub_key.exportKey().hex(), "aes_key":keys["aes_key"].hex(), "name": self.name})
        except Exception as e:
            return flask.jsonify({"okay": False})

    def get_message(self, ip, json_request):
        cipher_text = bytes.fromhex(json_request["message"])
        priv_key = None
        from_user = None
        for user in self.users_list:
            if user.ip == ip:
                priv_key = user.priv_key
                from_user = user
        if priv_key is None or from_user is None:
            return flask.jsonify({"okay": False})
        self.cryptographer.decode(priv_key, json_request["message"])
        decrypt_rsa = PKCS1_OAEP.new(priv_key)
        decrypted_text = decrypt_rsa.decrypt(cipher_text).decode()
        message = self.on_get_message(Message(decrypted_text, from_user))
        cipher_text = self.cryptographer.encode(from_user.pub_key, message.text)
        return flask.jsonify({"message": cipher_text})



