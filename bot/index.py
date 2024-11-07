import os
import telebot
import requests
from dotenv import load_dotenv
load_dotenv()
BACKEND_IP = os.getenv('BACKEND_IP', 'localhost')
BACKEND_PORT = os.getenv('BACKEND_PORT', '8000')
API_URL = f"http://{BACKEND_IP}:{BACKEND_PORT}/users"
BOT_TOKEN = os.getenv('BOT_TOKEN')
bot = telebot.TeleBot(BOT_TOKEN)

LANGUAGES = {
    'en': 'English',
    'vi': 'Vietnamese',
}

@bot.message_handler(commands=['start'])
def start_command(message):
    telegram_id = message.chat.id
    language = "en"

    user_data = {
        "telegram_id": telegram_id,
        "language": language
    }
    try:
        response = requests.post(API_URL+'/', json=user_data)
        if response.status_code == 201:
            bot.send_message(chat_id=telegram_id, text="Welcome! Your information has been saved.")
        elif response.status_code == 200:
            bot.send_message(chat_id=telegram_id, text="Welcome back! Your information has been updated.")
        else:
            bot.send_message(chat_id=telegram_id, text="Could not save your information. Please try again.")
    except requests.RequestException:
        bot.send_message(chat_id=telegram_id, text="Error connecting to the server. Please try again later.")

@bot.message_handler(commands=['setlang'])
def set_language(message):
    lang_code = message.text.split()[1] if len(message.text.split()) > 1 else None
    
    if lang_code in LANGUAGES:
        telegram_id = message.chat.id
        try:
            update_data = {
                "language": lang_code
            }

            update_response = requests.post(f"{API_URL}/{telegram_id}/update_lang/", json=update_data)

            if update_response.status_code == 200:
                bot.send_message(chat_id=message.chat.id, text=f"Language updated to {LANGUAGES[lang_code]}")
            elif update_response.status_code == 201:
                bot.send_message(chat_id=message.chat.id, text=f"Language set to {LANGUAGES[lang_code]}")
            else:
                bot.send_message(chat_id=message.chat.id, text="Failed to update language. Please try again.")
        
        except requests.RequestException:
            bot.send_message(chat_id=message.chat.id, text="Error connecting to the server. Please try again later.")
    else:
        bot.send_message(chat_id=message.chat.id, text="Invalid language code. Supported languages: " + ", ".join(LANGUAGES.keys()))

bot.polling()
bot.infinity_polling()
