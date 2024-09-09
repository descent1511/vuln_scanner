import os
import telebot
from .models import TelegramUser
import os
from dotenv import load_dotenv
BOT_TOKEN = os.getenv("BOT_TOKEN")
LANGUAGES = {
    'en': 'English',
    'vi': 'Vietnamese',
}

class TelegramBot:
    def __init__(self):
        self.bot = telebot.TeleBot(BOT_TOKEN)
        self.register_handlers()

    def register_handlers(self):
        @self.bot.message_handler(commands=['setlang'])
        def set_language(message):
            lang_code = message.text.split()[1] if len(message.text.split()) > 1 else None
            if lang_code in LANGUAGES:
                user, created = TelegramUser.objects.get_or_create(telegram_id=message.chat.id)
                if user.set_language(lang_code):
                    self.bot.send_message(chat_id=message.chat.id, text=f"Language set to {LANGUAGES[lang_code]}")
                else:
                    self.bot.send_message(chat_id=message.chat.id, text="Failed to set language.")
            else:
                self.bot.send_message(chat_id=message.chat.id, text="Invalid language code. Supported languages: " + ", ".join(LANGUAGES.keys()))

    def send_message(self,chat_id,  message):
        
        self.bot.send_message(chat_id=chat_id, text=message, parse_mode='Markdown')