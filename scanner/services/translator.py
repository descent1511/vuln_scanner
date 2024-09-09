import openai
import os
from dotenv import load_dotenv
load_dotenv()
openai.api_key = os.getenv("OPENAI_API_KEY")

def translate(text, source_lang="en", target_lang="vi"):
    messages = [
        {"role": "system", "content": "You are a helpful assistant that translates text."},
        {"role": "user", "content": f"Translate the following text from {source_lang} to {target_lang}: {text}"}
    ]
    
    response = openai.ChatCompletion.create(
        model="gpt-4",  # Use gpt-4 or gpt-3.5-turbo for chat-based models
        messages=messages,
        max_tokens=1000,
        temperature=0.3,
        n=1
    )

    translation = response['choices'][0]['message']['content'].strip()
    return translation
