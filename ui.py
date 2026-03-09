import flet as ft
import user

class LoginUi():
    def __init__(self,loc):
        self.input_name=None
        self.loc=loc
    def guest_login(self,page: ft.Page):

        page.window_width = 350
        page.window_height = 200
        page.window_resizable = False
        page.add(ft.Container())
        name_input = ft.TextField(label=self.loc.get("input_name_login"), autofocus=True)
        def login(e):
            if name_input.value!=None:
                self.input_name=name_input.value
                page.window_destroy()

        # dlg = ft.AlertDialog(
        #     title=,
        #     content=ft.Container(name_input, height=60),  # Фиксируем высоту контента
        #     actions=[ft.TextButton(self.loc.get("login_enter"), on_click=login)]
        # )
        page.add(ft.Text(self.loc.get("login_title")),ft.Container(content=name_input, height=60),ft.TextButton(self.loc.get("login_enter"), on_click=login))
        #dlg.open = True
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
            on_click=lambda e: on_click(user)
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



class ChatWindow():
    def __init__(self,session,page=None,message_send=MessageSend(),loc=None):
        self.page =page
        self.session=session
        self.message_send=message_send
        self.on_send_func = None
        self.loc=loc
    def render(self,talking,chats):

        def send(e):
            self.on_send_func(self.session,talking,user.Message(message_input.value,self.session,"blue100"))
            #self.message_send.send(self.session,talking,Message(message_input.value,self.session,"blue"))
            talking.chat_history.append(user.Message(message_input.value,self.session,"blue100"))
            message_input.value=""

        self.page.padding = 0
        chats=user.UserList([user.User(f"test{i}") for i in range(3)]).get_controls(lambda x:print("hello")) # FOR TEST ONLY!
        contacts = ft.Column(
            expand=True,
            scroll="auto",

            controls=chats
        )
        sidebar = ft.Container(
            content=contacts,
            width=350,
            height=self.page.window_height,
            bgcolor="#2A2A31",
            padding=10,
            border=ft.border.only(right=ft.border.BorderSide(0.75, "black"))
        )
        chat_history = ft.Column(expand=True, scroll="auto", spacing=10)

        message_input = ft.TextField(hint_text=self.loc.get("message_input_placeholder"), expand=True, on_submit=send)
        print(hasattr(talking,"chat_history"))
        message_typer=ft.Row([message_input, ft.IconButton(icon="send", on_click=send,)])
        if hasattr(talking,"chat_history"):

            chat_history.controls = talking.chat_history.get_controls()
            chat_screen = ft.Container(
                expand=True,
                padding=20,
                content=ft.Column([
                    chat_history,
                    message_typer
                ])
            )
        else:
            # chat_screen = ft.Container(
            #     expand=True,
            #     padding=20,
            #     content=ft.Column(
            #         controls=[
            #             ft.Text(self.loc.get("contacts_placeholder"), size=16)
            #         ],
            #         horizontal_alignment="center",
            #         alignment="center",
            #     ),
            #     alignment=ft.alignment.center
            # )
            chat_screen = ft.Container( # FOR TEST ONLY!
                expand=True,
                padding=20,
                content=ft.Column([
                    ft.Column(expand=True, scroll="auto", spacing=10, controls=user.MessageList([user.Message(i,self.session,"blue") for i in ["Привет","как дела?"]]+[user.Message(i,user.User("test"),"gray") for i in ["Норм","как ты?"]]).get_controls()),
                    message_typer
                ])
            )
        self.page.controls.clear()
        self.page.add(
            ft.Row(
                controls=[sidebar, chat_screen],
                expand=True,
                spacing=0

            )
        )
        self.page.update()


    def set_page(self,page):
        self.page=page
        self.render(None,[])
        return 0
