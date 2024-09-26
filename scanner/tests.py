from django.test import TestCase
from unittest.mock import patch
from .models import TelegramUser
from .telegram_bot import TelegramBot
import os

class TelegramBotTestCase(TestCase):
    def setUp(self):
        # Create a sample TelegramUser for testing
        self.user = TelegramUser.objects.create(telegram_id=os.getenv("TELEGRAM_ID"), language='en')
        # Instantiate your TelegramBot
        self.bot = TelegramBot()

    @patch('telebot.TeleBot.send_message')
    def test_set_language_valid(self, mock_send_message):
        # Simulate the /setlang command with a valid language code
        class MockMessage:
            chat = type('obj', (object,), {'id': self.user.telegram_id})
            text = '/setlang vi'

        self.bot.bot.message_handlers[0]['function'](MockMessage())
        
        # Refresh user data from the database
        self.user.refresh_from_db()

        # Check if the language was set correctly
        self.assertEqual(self.user.language, 'vi')
        # Verify that send_message was called with the expected response
        mock_send_message.assert_called_with(chat_id=self.user.telegram_id, text="Language set to Vietnamese")

    @patch('telebot.TeleBot.send_message')
    def test_set_language_invalid(self, mock_send_message):
        # Simulate the /setlang command with an invalid language code
        class MockMessage:
            chat = type('obj', (object,), {'id': self.user.telegram_id})
            text = '/setlang xyz'

        self.bot.bot.message_handlers[0]['function'](MockMessage())

        # Verify that send_message was called with an error message
        mock_send_message.assert_called_with(chat_id=self.user.telegram_id, text="Invalid language code. Supported languages: en, vi")
