import json

from utils import cryptographer
class SaveUser():
    def __init__(self,name,password,ip,auth):
        self.name=name
        self.password=password.encode()
        self.cryptographer = cryptographer.Cryptographer()
        self.messages={}
        self.ip=ip
        self.auth=auth
    def save_user(self):
        with open("user","wb") as f:
            f.write(self.cryptographer.encode_aes(json.dumps({"name": self.name,"messages":self.messages}).encode(),(self.password + b'\x00' * 32)[:32] ))

    def load_user(self):
        with open("user","rb") as f:
            json_data = json.loads(self.cryptographer.decode_aes(f.read(),(self.password + b'\x00' * 32)[:32] ))
            self.name=json_data["name"]
            self.messages=json_data["messages"]
    def json(self):
        return {"name":self.name,"ip":self.ip,}
