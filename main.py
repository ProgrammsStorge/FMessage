import logging
import re
import socket
import sys
import threading
import flask
import requests
from flask import Flask
import client
import notifications
from utils import cryptographer,localization
import ui
from user import *
import server
import flet as ft
from utils.config import Config
from utils.cryptographer import UsernameValidator
from notifications import Notification
from utils.saver import SaveUser


def get_my_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
    finally:
        s.close()
    return ip

def extract_domains(text):
    if not text:
        return []
    pattern = r'(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}'
    matches = re.findall(pattern, text)
    unique_domains = list(set(domain.lower() for domain in matches))
    return unique_domains

def main():
    app = Flask(__name__)
    @app.route("/message", methods=['POST'])
    def get_message_route():
        data = flask.request.get_json(force=True)
        return app_server.get_message(flask.request.remote_addr,data)
    @app.route("/document/<document_name>", methods=['GET',"POST"])
    def get_document_route(document_name):
        return app_server.get_document(flask.request.remote_addr, document_name)
    @app.route("/ping", methods=['POST'])
    def ping_route():
        return flask.jsonify( app_server.ping(None,None) )
    @app.route("/open_window", methods=['POST'])
    def open_window_route():
        if flask.request.get_json(force=True)["fingerprint"] == cryptographer.FingerPrint().fingerprint:
            open_window()
            return flask.jsonify({"ok": True})
        else:
            return flask.jsonify({"ok": False})
    @app.route("/handshake", methods=['POST'])
    def handshake_route():
        data = flask.request.get_json(force=True)
        return app_server.handshake(flask.request.remote_addr,data)
    def set_talking(user):
        global talking
        talking = user
        render()
    def new_user(user):
        if session.auth:
            if session.messages.get(user.name) != None:user.chat_history=MessageList([Message(m["text"],session if m["by_me"] else user,config.get("Visual","own_message_color","blue500") if m["by_me"] else config.get("Visual", "other_message_color", "gray")) for m in session.messages[user.name]])
        users_list.append(user)
        render()
    def get_message(text, user,documents):
        color = config.get("Visual", "other_message_color", "gray")
        for url in extract_domains(text):
            if url in bad_domains:
                text.replace(url,"[phishing link]")
                text+=" [phishing]"
                color="red"
        if session.auth:
            if session.messages.get(user.name) == None: session.messages[user.name] = []
            session.messages[user.name].append({"text":text,"by_me": False})
            session.save_user()
        user.chat_history.append(Message(text,user,color,documents,session))
        if talking==user: render()
        if not opn_wnd:
            Notification(user.name, text, onclick=open_window).view()
    def send_message(sender,target,message):
        if session.auth:
            if session.messages.get(target.name) == None: session.messages[target.name] = []
            session.messages[target.name].append({"text":message.text,"by_me": True})
            session.save_user()
        message_sender.send_message(message,target)
    def render():
        global talking
        chat_window.render(talking,users_list.get_controls(set_talking))
    if cryptographer.MITMChecker().check():
        __import__("ctypes").windll.user32.MessageBoxW(0, "A repeat of MAC addresses has been detected on your network", "Warning", 0)
        sys.exit(500)
    config = Config("config.ini")
    name_validator = UsernameValidator()
    fingerprint=cryptographer.FingerPrint()
    loc = localization.Localization(config.get("Localization","language","eng"))
    log = logging.getLogger('werkzeug')
    log.setLevel(logging.ERROR)
    port=int(config.get("Connect","port",55555))
    print(fingerprint.fingerprint)
    try:
        r=requests.post(f"http://127.0.0.1:{port}/ping",timeout=1).json()
        if r.get("ok") != None and r.get("ok") == True:
            requests.post(f"http://127.0.0.1:{port}/open_window",json={"fingerprint":fingerprint.fingerprint}, timeout=1).json()
            sys.exit(0)
    except Exception as e:
        pass
        #print(e)
    with open("bad_domains.txt","r",encoding="utf-8") as f:
        bad_domains = f.read().splitlines()
    with open("whitelist.txt","r",encoding="utf-8") as f:
        whitelist = f.read().splitlines()
    auth=config.get("Account","guest","true").lower() == "false"
    login_ui = ui.LoginUi(loc,name_validator, auth)
    ft.app(target=login_ui.guest_login)
    if login_ui.input_name==None:sys.exit(0)
    if not auth:
        session = SaveUser(login_ui.input_name,"",get_my_ip(),auth)
    else:
        session = SaveUser("", login_ui.input_name, get_my_ip(), auth)
        session.load_user()
    chat_window = ui.ChatWindow(session,loc=loc,config=config)
    cryptograph= cryptographer.Cryptographer()
    print(cryptograph.generate_keys()["aes_key"])
    users_list = UserList([])
    chat_window.on_send_func=send_message
    app_server = server.Server(get_my_ip(),port,cryptograph,users_list,session,whitelist)
    message_sender = client.MessageSend(port, get_my_ip(), cryptograph, app_server)
    message_sender.on_get_func=get_message
    app_server.on_new_func=new_user
    app_server.on_get_func=get_message
    threading.Thread(target=app.run, args=("0.0.0.0", port), daemon=True).start()
    handshaker=client.Handshaker(port,get_my_ip(),session,users_list,new_user,whitelist)
    handshaker.on_new_func=new_user
    scaner = client.Scaner(port,get_my_ip(),handshaker)
    chat_window.handshaker=handshaker
    scaner.scan()


    def open_window(*args):
        chat_window.open_window(True)

    ft.app(target=chat_window.set_page)


if __name__=="__main__":
    opn_wnd = True
    talking = User("placeholder", None, None, get_my_ip(),placeholder=True)
    main()
else:
    sys.exit(999)