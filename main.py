import logging
import socket
import sys
import threading
import flask
from flask import Flask
import client
from utils import cryptographer,localization
import ui
from user import *
import server
import flet as ft



def get_my_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
    finally:
        s.close()
    return ip

def main():
    app = Flask(__name__)

    @app.route("/message", methods=['POST'])
    def get_message_route():
        data = flask.request.get_json(force=True)
        return app_server.get_message(flask.request.remote_addr,data)

    @app.route("/ping", methods=['POST'])
    def ping_route():

       # print(app_server.ping(flask.request.remote_addr,flask.request.json),flask.request.remote_addr,flask.request.json)
        return flask.jsonify( app_server.ping(None,None) )

    @app.route("/handshake", methods=['POST'])
    def handshake_route():
        data = flask.request.get_json(force=True)
        return app_server.handshake(flask.request.remote_addr,data)

    def set_talking(user):
        global talking
        talking = user
        render()

    def new_user(user):
        users_list.append(user)
        render()
        print(f"Привет, {user.name}!")

    def get_message(text, user):
        user.chat_history.append(Message(text,user,"200gray"))
        if talking==user: render()

    def send_message(sender,target,message):
        message_sender.send_message(message,target)

    def render():
        global talking
        chat_window.render(talking,users_list.get_controls(set_talking))

    loc = localization.Localization("ru")
    log = logging.getLogger('werkzeug')
    log.setLevel(logging.ERROR)
    port="55555"
    print("test", loc.get("login_title"), loc.get("login_enter"), loc.get("input_name_login"))
    login_ui = ui.LoginUi(loc)
    #login_ui.input_name="test"
    ft.app(target=login_ui.guest_login)
    session = User(login_ui.input_name)
    chat_window = ui.ChatWindow(session,loc=loc)
    cryptograph= cryptographer.Cryptographer()
    users_list = UserList([])
    message_sender=client.MessageSend(port,get_my_ip(),cryptograph)
    talking.chat_history.append(Message("Выберите кому хотите отправить сообщение.",talking,"green300"))
    chat_window.on_send_func=send_message
    app_server = server.Server(get_my_ip(),port,cryptograph,users_list,session)
    app_server.on_new_func=new_user
    app_server.on_get_func=get_message
    threading.Thread(target=app.run, args=("0.0.0.0", port), daemon=True).start()
    handshaker=client.Handshaker(port,get_my_ip(),session,users_list,new_user)
    handshaker.on_new_func=new_user
    scaner = client.Scaner(port,get_my_ip(),handshaker)
    scaner.scan()
    ft.app(target=chat_window.set_page)



if __name__=="__main__":
    talking = User("placeholder", None, None, get_my_ip())
    main()
else:
    import ctypes
    ctypes.windll.user32.MessageBoxW(0, u"Ты что творишь?", u"Эй", 16)
    ctypes.windll.user32.MessageBoxW(0, u"Этот файл надо запускать а не импортировать", u"Эй", 16)
    sys.exit(999)