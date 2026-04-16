import traceback

import flask
from utils.cryptographer import *
from user import *

class Server():
    def __init__(self,ip,port,cryptographer,user_list,session,whitelist=[]):
        self.ip = ip
        self.port = port
        self.session = session
        self.cryptographer = cryptographer
        self.user_list = user_list
        self.on_get_func=None
        self.on_new_func = None
        self.files={}
        self.whitelist = whitelist
    def ping(self,ip,json_request):
        return {"ok": True, "name": self.session.name}

    def handshake(self,ip,json_request):
        try:
            if len([i for i in self.whitelist if i.replace(" ","") !="" and (len(i)==0 or i[0]!="#")])>0:
                if not ip in [i for i in self.whitelist if i.replace(" ","") !="" and (len(i)==0 or i[0]!="#")] :
                    return flask.jsonify({"okay": False})
            self.user_list.users = [u for u in self.user_list.users if u.ip != ip]
            keys = self.cryptographer.generate_keys()
            priv_key = keys["priv_key"]
            pub_key = keys["pub_key"]
            user = User(json_request["name"], priv_key, RSA.import_key(bytes.fromhex(json_request["pub_key"])), ip,
                        bytes.fromhex(json_request["aes_key"]))
            if UsernameValidator().check_username(json_request["name"]):
                print(self.cryptographer.encode_rsa(user.pub_key, "User rsa key valid"))
                self.cryptographer.decode_aes(self.cryptographer.encode_aes(b"User aes key valid",user.aes_key),
                                              user.aes_key)
                self.on_new_func(user)
                return flask.jsonify({"pub_key": pub_key.exportKey().hex(), "aes_key":json_request["aes_key"], "name": self.session.name})
            else:
                return flask.jsonify({"okay": False})
        except Exception as e:
            return flask.jsonify({"okay": False})

    def get_document(self,ip,document_name):
        try:
            if self.files.get(document_name).target.ip == ip:
                for user in self.user_list:
                    if user.ip == ip:
                        return flask.Response(self.cryptographer.encode_aes(self.files.get(document_name).file_bytes,user.aes_key), mimetype='application/octet-stream')
        except Exception as e:
            pass

    def get_message(self,ip,json_request):
        cipher_text = bytes.fromhex(json_request["message"])
        priv_key = None
        from_user = None
        for user in self.user_list:
            if user.ip == ip:
                priv_key = user.priv_key
                from_user = user
        if priv_key is None or from_user is None:
            return flask.jsonify({"okay": False})
        decrypted_text=self.cryptographer.decode_rsa(priv_key, json_request["message"])
        self.on_get_func(decrypted_text, from_user,json_request["documents"])
        return flask.jsonify({"okay": False})

    def get_message_handler(self,func):
        self.on_get_func = func
        return func
    def new_user_handler(self,func):
        self.on_new_func = func
        return func
