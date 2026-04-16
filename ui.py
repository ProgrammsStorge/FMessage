import os.path
import subprocess
import sys
import ctypes
import flet
import flet as ft
import win32con
import win32gui

import user
from notifications import Notification
from utils.config import Config
from utils.saver import SaveUser


class LoginUi():
    def __init__(self,loc,name_validator,auth):
        self.input_name=None
        self.loc=loc
        self.name_validator=name_validator
        self.auth=auth

    def guest_login(self,page: ft.Page):
        page.theme_mode = ft.ThemeMode.DARK
        page.window_width = 350
        page.window_height = 400
        page.window_resizable = False
        page.add(ft.Container())

        def login(e):
            if not self.auth:
                if name_input.value!=None and self.name_validator.check_username(name_input.value):
                    self.input_name=name_input.value

                    page.window_destroy()
                else:
                    ctypes.windll.user32.MessageBoxW(0, self.loc.get("dont_valid_username"), u"Wrong username", 16)
            elif not os.path.exists("user"):
                try:
                    SaveUser(name_input.value,password_input.value,"",True).save_user()
                    self.input_name=password_input.value
                    page.window_destroy()
                except Exception as e:
                    print(e)
                    ctypes.windll.user32.MessageBoxW(0, self.loc.get("error"), u"Error", 16)
            else:
                try:
                    SaveUser("",password_input.value,"",True).load_user()
                    self.input_name=password_input.value
                    page.window_destroy()
                except:
                    ctypes.windll.user32.MessageBoxW(0, self.loc.get("dont_valid_password"), u"Wrong password", 16)

        name_input = ft.TextField(label=self.loc.get("input_name_login"), autofocus=True, on_submit=login)
        password_input = ft.TextField(label=self.loc.get("input_password_login"), autofocus=True, on_submit=login)
        if os.path.exists("user") or not self.auth:
            page.add(ft.Text(self.loc.get("login_title")),ft.Container(content=ft.Column(([password_input] if self.auth else [name_input])), height=60),ft.TextButton(self.loc.get("login_enter"), on_click=login))
        else:
            page.add(ft.Text(self.loc.get("login_title")),
                     ft.Container(content=ft.Column([name_input,password_input]), height=120),
                     ft.TextButton(self.loc.get("login_enter"), on_click=login))
        page.update()


class IconGenerator():
    def __init__(self,colors=["red400", "blue400", "green400", "orange400", "purple400", "teal400", "amber400", "cyan400","indigo400"]):
        self.colors=colors
    def create_icon_from_name(self,user):
        return ft.CircleAvatar(content=ft.Text("".join([i[0] for i in user.name.split()][:3])),
                        bgcolor=self.colors[sum([int(ord(i)) for i in user.name]) % len(self.colors)])

class Icon():
    def __init__(self,user):
        self.user=user
        self.controls = IconGenerator().create_icon_from_name(user)


class CardGenerator():
    def __init__(self):
        self.icon_generator = IconGenerator()
    def create_card(self,user,on_click):
        return ft.ListTile(
            leading=self.icon_generator.create_icon_from_name(user),
            title=ft.Text(user.name),
            subtitle=ft.Text("Пользователь"),
            on_click=lambda e: on_click(user),
            height=40
        )

class MessageSend():
    def __init__(self,on_send_func=None):
        self.on_send_func=on_send_func
    def send(self,sender,target,message):
        sender.chat_history.append(message)
        if self.on_send_func:
            self.on_send_func(message.text,target)
    def send_handler(self,func):
        self.on_send_func=func
        return func

class OpenFile():
    def open_file(self,target):
        try:
            filter = "All Files\0*.*\0Images\0*.png\0"
            fname, customfilter, flags = win32gui.GetOpenFileNameW(
                InitialDir="C:\\Users\\%Username%",
                Flags=win32con.OFN_EXPLORER,
                Title='Choose file',
                Filter=filter,
                FilterIndex=0)
            with open(fname,'rb') as f:
                return user.File(fname,target,f.read())
        except Exception as e:return None



class ChatWindow():
    def __init__(self,session,page=None,message_send=MessageSend(),loc=None,config=Config("config.ini"),icon_generator=IconGenerator(),handshaker=None):
        self.page =page
        self.session=session
        self.message_send=message_send
        self.on_send_func = None
        self.config=config
        self.icon_generator = icon_generator
        self.open_file=OpenFile()
        self.loc=loc
        self.attach_files=[]
        self.handshaker=handshaker

    def open_window(self,on=True):
        self.page.window_visible = on
        self.page.update()
    def open_window_event(self,e):
        self.page.window_visible = True
        self.page.update()
    def render(self,talking,chats):
        def on_window_event(e):
            if e.data == "close":
                self.open_window(False)
        self.page.window_prevent_close = True
        self.page.on_window_event = on_window_event
        self.page.theme_mode = ft.ThemeMode.DARK
        own_message_color=self.config.get("Visual","own_message_color","blue500")
        search_color = self.config.get("Visual", "search_color", "#424247")
        message_input_color = self.config.get("Visual", "message_input_color", "#2A2A31")
        sidebar_color = self.config.get("Visual", "sidebar_color", "#2A2A31")
        other_message_color = self.config.get("Visual", "other_message_color", "gray")
        up_bar_color = self.config.get("Visual", "up_bar_color", "#2A2A31")
        buttons_bar_color = self.config.get("Visual", "buttons_bar_color", "#282b30")
        def send(e):
            talking.chat_history.append(user.Message(message_input.value+(f"\n{' '.join([f'[{f.path}]' for f in self.attach_files])}" if self.attach_files!=[] else ""), self.session, own_message_color))
            self.render(talking, chats)
            self.on_send_func(self.session,talking,user.Message(message_input.value,self.session,own_message_color,self.attach_files,talking))
            #self.message_send.send(self.session,talking,Message(message_input.value,self.session,"blue"))
            message_input.value=""


        def search(e):
            gram_count = 3
            query=search_input.value
            if not query or len(query) < gram_count:
                q_trigrams = {query} if query else set()
            else:
                q_trigrams = set(query[i:i + gram_count] for i in range(len(query) - 2))
            results = []
            for data_user in chats:
                data=user.name
                if len(data) < gram_count:
                    t_trigrams = {data} if data else set()
                else:
                    t_trigrams = set(data[i:i + gram_count] for i in range(len(data) - 2))
                score = len(q_trigrams & t_trigrams)
                results.append((data_user, score))
            results.sort(key=lambda x: x[1], reverse=True)
            users=[i[0] for i in results]
            self.contacts = ft.Column([search_input, ft.Column(
                expand=True,
                scroll="auto",
                controls=users
            )])
            if ''.join(char for char in query if not char.isdigit())=="...:":
                self.handshaker.send_handshake(query)

        def add_file(e):
            file= self.open_file.open_file(talking)
            if file != None:
                self.attach_files.append(file)
            self.render(talking, chats)
        self.page.padding = 0
        #chats=user.UserList([user.User(f"test{i}") for i in range(3)]).get_controls(lambda x:print("hello")) # FOR TEST ONLY!
        search_input = ft.TextField(prefix_icon="search",hint_text=self.loc.get("contact_search"), height=45, border_radius=360,
                                    border_width=2, border_color=search_color,
                                    focused_border_color=search_color, on_submit=search)
        buttons_menu=ft.Container(content=ft.Row([ft.IconButton("settings",on_click=lambda e: subprocess.Popen("config_editor.exe")),ft.IconButton("close",on_click=lambda e:self.page.window_destroy())]),bgcolor=buttons_bar_color,width=350,margin=0)

        self.contacts = ft.Column([search_input,ft.Column(
            expand=True,
            scroll="auto",
            controls=chats
        ),buttons_menu])

        chat_history = ft.Column(expand=True, scroll="auto", spacing=10,)

        message_input =  ft.TextField(hint_text=self.loc.get("message_input_placeholder"),height=25,border_radius=360,border_width=2, expand=True, on_submit=send, border_color=message_input_color,focused_border_color=message_input_color,)
        files_content=ft.Row([ft.TextButton(
            text=att_file.path,
            on_click=lambda e: [self.attach_files.remove(att_file),self.render(talking,chats)],
            height=40
        ) for att_file in self.attach_files])
        message_typer=ft.Container(content=ft.Column([files_content,ft.Row([flet.IconButton(icon="attach_file",on_click=add_file),message_input, ft.IconButton(icon="send", on_click=send,)])]),bgcolor=message_input_color,margin=0,padding=10,shadow=ft.BoxShadow(
                spread_radius=1,
                blur_radius=15,
                color=ft.colors.with_opacity(0.15, ft.colors.BLACK),
                offset=ft.Offset(0, -5),
            ),)
        up_bar = ft.Container(content=ft.Row([self.icon_generator.create_icon_from_name(talking), ft.Text(talking.name)]),
                                     bgcolor=up_bar_color, margin=0, padding=10,shadow=ft.BoxShadow(
                spread_radius=1,
                blur_radius=15,
                color=ft.colors.with_opacity(0.15, ft.colors.BLACK),
                offset=ft.Offset(0, 5),
            ),)
        sidebar = ft.Container(
            content=self.contacts,
            width=350,
            # height=self.page.window_height,
            bgcolor=sidebar_color,
            padding=3,
            margin=0,
            border=ft.border.only(right=ft.border.BorderSide(0.75, "black")),

            shadow=ft.BoxShadow(
                spread_radius=1,
                blur_radius=15,
                color=ft.colors.with_opacity(0.15, ft.colors.BLACK),
                offset=ft.Offset(5, 0),
            ),

        )
        if hasattr(talking,"chat_history") and talking.placeholder == False:

            chat_history.controls = talking.chat_history.get_controls()
            chat_screen = ft.Container(
                expand=True,
                padding=0,
                content=ft.Column([up_bar,
                    ft.Container(chat_history, padding=20,expand=True),
                    message_typer
                ])
            )
        else:
            chat_screen = ft.Container(
                expand=True,
                padding=20,
                content=ft.Column(
                    controls=[
                        ft.Text(self.loc.get("contacts_placeholder"), size=16)
                    ],
                    horizontal_alignment="center",
                    alignment="center",
                ),
                alignment=ft.alignment.center
            )
        self.page.controls.clear()
        self.page.add(

            ft.Row(
                controls=[sidebar, chat_screen],
                expand=True,
                vertical_alignment="STRETCH".lower(),
                spacing=0

            ),

        )
        self.page.update()


    def set_page(self,page):
        self.page=page
        self.render(user.User("placeholder",placeholder=True),[])
        return 0
