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
    def __init__(self,text,sender,color):
        self.text = text
        self.sender = sender
        self.color=color
        self.icon = Icon(sender)
    def get_controls(self):
        return ft.Row(
            controls=[self.icon.controls,
                      ft.Container(content=ft.Text(self.text, color="white"),
                                   bgcolor=self.color, border_radius=15, padding=10)],
            alignment="start"
        )

class User():
    def __init__(self, name,priv_key=None, pub_key=None,ip=""):
        self.ip=ip
        self.name = name
        self.pub_key = pub_key
        self.priv_key = priv_key
        self.chat_history=MessageList([])
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
