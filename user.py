import hashlib
import random
import string
import textwrap

import client
import utils.config
import utils.cryptographer
from ui import Icon,CardGenerator
import flet as ft

class MessageList():
    def __init__(self,messages):
        self.messages = messages
    def __getitem__(self, item):
        return self.messages[item]
    def __iter__(self):
        return iter(self.messages)
    def append(self,message):
        self.messages.append(message)
    def get_controls(self):
        return [i.get_controls() for i in self.messages]

class Message():
    def __init__(self,text,sender,color,documents=[],target=""):
        self.text = text
        self.sender = sender
        self.color=color
        self.target=target
        self.icon = Icon(sender)
        self.documents = documents
    def get_controls(self):
        return ft.Row(
            controls=[self.icon.controls,
                      ft.Container(content=ft.Row([ft.Text('\n'.join(textwrap.wrap(self.text, width=35))+"\n", color="white")] + [ft.TextButton(
            text=d,
            on_click=lambda e: client.DocumentInstaller(int(utils.config.Config("config.ini").get("Connect","port",55555)),utils.cryptographer.Cryptographer()).install(d,self.sender),
            height=40
        ) for d in self.documents]),
                                   bgcolor=self.color, border_radius=15, padding=10)],
            alignment="start"
        )

class File():
    def __init__(self,path,target,file_bytes):
        try:self.rnd_key=hashlib.sha256("".join([random.choice(string.printable) for i in range(500)]).encode()).hexdigest()[0:10]+"."+path.split(".")[-1]
        except:self.rnd_key=hashlib.sha256("".join([random.choice(string.printable) for i in range(500)]).encode()).hexdigest()[0:10]
        self.path = path
        self.target = target
        self.file_bytes = file_bytes

class User():
    def __init__(self, name,priv_key=None, pub_key=None,ip="",aes_key=None,bot=False,port=50000,placeholder=False):
        self.ip=ip
        self.name = name
        self.pub_key = pub_key
        self.aes_key = aes_key
        self.priv_key = priv_key
        self.chat_history=MessageList([])
        self.bot=bot
        self.port=port
        self.placeholder=placeholder
    def json(self):
        return {"name":self.name,"ip":self.ip,}

class UserList():
    def __init__(self, users):
        self.users = users
        self.card_generator = CardGenerator()
    def __getitem__(self, item):
        return self.users[item]
    def remove(self,user):
        self.users.remove(user)
    def __iter__(self):
        return iter(self.users)
    def append(self, user):
        self.users.append(user)
    def get_controls(self,on_click=None):
        return [self.card_generator.create_card(user,on_click) for user in self.users]
