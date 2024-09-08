from googletrans import Translator

def translate(text, src_language='en', dest_language='vi'):
    translator = Translator()
    translated = translator.translate(text, src=src_language, dest=dest_language)
    return translated.text

