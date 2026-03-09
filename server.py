import flask
from utils.cryptographer import *
from user import *

class Server():
    def __init__(self,ip,port,cryptographer,user_list,session):
        self.ip = ip
        self.port = port
        self.session = session
        self.cryptographer = cryptographer
        self.user_list = user_list
        self.on_get_func=None
        self.on_new_func = None
    def ping(self,ip,json_request):

        return {"ok": True, "name": self.session.name}

    def handshake(self,ip,json_request):
        try:
            #json_request = flask.request.json
            for user in self.user_list:
                if user.name == json_request["name"] and user.ip == json_request["ip"]:
                    self.user_list.remove(user)
            keys = self.cryptographer.generate_keys()
            priv_key = keys["priv_key"]
            pub_key = keys["pub_key"]
            #ip = flask.request.remote_addr
            user = User(json_request["name"], priv_key, RSA.import_key(json_request["pub_key"]), ip)
            self.user_list.append(user)
            self.on_new_func(user)
            return flask.jsonify({"pub_key": pub_key.exportKey().decode(), "name": self.session.name})
        except Exception as e:
            print(e)
            return flask.jsonify({"okay": False})
            #return None

    def get_message(self,ip,json_request):
        #ip = flask.request.remote_addr
        #json_request = flask.request.json
        cipher_text = bytes.fromhex(json_request["message"])
        priv_key = None
        from_user = None
        for user in self.user_list:
            if user.ip == ip:
                priv_key = user.priv_key
                from_user = user
        if priv_key is None or from_user is None:
            # send_handshake(ip)
            return flask.jsonify({"okay": False})
        self.cryptographer.decode(priv_key,json_request["message"])
        decrypt_rsa = PKCS1_OAEP.new(priv_key)
        decrypted_text = decrypt_rsa.decrypt(cipher_text).decode()
        self.on_get_func(decrypted_text, from_user)
        return flask.jsonify({"okay": False})

    def get_message_handler(self,func):
        self.on_get_func = func
        return func
    def new_user_handler(self,func):
        self.on_new_func = func
        return func
