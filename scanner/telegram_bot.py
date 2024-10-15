import os
import telebot  # Import the telebot library for interacting with the Telegram Bot API
from .models import TelegramUser  # Import the TelegramUser model to manage user data
from dotenv import load_dotenv  # Import to load environment variables from a .env file

# Define supported languages with their codes
LANGUAGES = {
    'en': 'English',
    'vi': 'Vietnamese',
}

# Class to manage the Telegram bot's functionality
class TelegramBot:
    def __init__(self):
        # Initialize the bot with the token from environment variables
        self.bot = telebot.TeleBot(os.getenv("BOT_TOKEN"))
        self.register_handlers()  # Register message handlers for the bot

    # Method to register bot handlers
    def register_handlers(self):
        # Handler for the /setlang command to set the language
        @self.bot.message_handler(commands=['setlang'])
        def set_language(message):
            # Extract the language code from the command
            lang_code = message.text.split()[1] if len(message.text.split()) > 1 else None

            # Check if the provided language code is supported
            if lang_code in LANGUAGES:
                # Retrieve or create a TelegramUser entry for the user
                user, created = TelegramUser.objects.get_or_create(telegram_id=message.chat.id)
                
                # Attempt to set the user's language
                if user.set_language(lang_code):
                    # Inform the user that the language has been set successfully
                    self.bot.send_message(chat_id=message.chat.id, text=f"Language set to {LANGUAGES[lang_code]}")
                else:
                    # Inform the user of a failure to set the language
                    self.bot.send_message(chat_id=message.chat.id, text="Failed to set language.")
            else:
                # Inform the user of invalid language codes and list supported options
                self.bot.send_message(chat_id=message.chat.id, text="Invalid language code. Supported languages: " + ", ".join(LANGUAGES.keys()))

    # Method to send a message to a specific chat
    def send_message(self, chat_id, message=None, pdf_path=None):
        print(f"Opening PDF file at: {pdf_path}")
        if message and pdf_path:

            with open(pdf_path, 'rb') as pdf_file:
                self.bot.send_document(chat_id=chat_id, document=pdf_file, caption=message, parse_mode='Markdown')
        elif message:
            # Case when only a message is provided
            self.bot.send_message(chat_id=chat_id, text=message, parse_mode='Markdown')
        elif pdf_path:
            # Case when only a PDF is provided
            with open(pdf_path, 'rb') as pdf_file:
                self.bot.send_document(chat_id=chat_id, document=pdf_file)
        else:
            # Case when neither a message nor a PDF is provided
            print("No message or PDF provided to send.")

