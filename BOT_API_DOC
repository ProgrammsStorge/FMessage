## 1. Быстрый старт
Чтобы запустить бота, нужно выполнить три шага:
Создать объект Bot.
Назначить функции-обработчики через декораторы.
Запустить сервер методом start().

```
from bot import Bot
bot = Bot(name="MyBot", port=5000)
bot.start()
```

## 2. Обработчики событий

@bot.new_user_handler — Подключение пользователя
Этот декоратор регистрирует функцию, которая вызывается сразу после успешного хендшейка (когда клиент впервые подключается и обменивается ключами).
Аргумент функции: Объект user.
user.name: Имя клиента (передается при хендшейке).
user.ip: IP-адрес клиента.
user.pub_key: Публичный RSA-ключ клиента.
Возвращаемое значение: Не требуется (или None).
Зачем нужно: Логирование подключений, подготовка данных под конкретного юзера.

```
@bot.new_user_handler
def on_connect(user):
    print(f"{user.name}: {user.ip}")
```

@bot.new_message_handler — Получение сообщения
Это основной обработчики событий. Функция вызывается каждый раз, когда приходит сообщение от любого подключенного пользователя.
Аргумент функции: Объект message.
message.text: Текст сообщения (строка str).
message.sender: Объект User, который отправил сообщение. Ты можешь обратиться к message.sender.name или message.sender.ip.
Возвращаемое значение: Строка (str).
То, что ты вернешь из этой функции, будет автоматически зашифровано публичным ключом отправителя и отправлено ему обратно как ответ.

```
@bot.new_message_handler
def on_message(message):
    text = message.text
    sender_name = message.sender.name
  
    if "привет" in text.lower():
        return f"Привет, {sender_name}!"
    
    return f"Ты написал: {text}"
```

## 3. Пример

Простой эхо бот с логированием подключения:

```
from fbot import Bot
from fbot.user import Message

my_bot = Bot(name="Simple bot", port=5000)

@my_bot.new_user_handler
def handle_new_user(user):
    print(f"{user.name}: {user.ip}")

@my_bot.new_message_handler
def handle_message(message: Message):
    return Message(f"{message.sender.name}: {message.text}")

if __name__ == "__main__":
    my_bot.start()
```
