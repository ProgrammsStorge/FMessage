class MessageList():
    def __init__(self,messages):
        self.messages = messages
    def __getitem__(self, item):
        return self.messages[item]
    def __iter__(self):
        return iter(self.messages)
    def append(self,message):
        self.messages.append(message)

class Message():
    def __init__(self,text,sender="placeholder"):
        self.text = text
        self.sender = sender

class User():
    def __init__(self, name,priv_key=None, pub_key=None,ip="",aes_key=None):
        self.ip=ip
        self.name = name
        self.pub_key = pub_key
        self.aes_key = aes_key
        self.priv_key = priv_key
        self.chat_history=MessageList([])
    def json(self):
        return {"name":self.name,"ip":self.ip,}

class UserList():
    def __init__(self, users):
        self.users = users
    def __getitem__(self, item):
        return self.users[item]
    def remove(self,user):
        self.users.remove(user)
    def __iter__(self):
        return iter(self.users)
    def append(self, user):
        self.users.append(user)
