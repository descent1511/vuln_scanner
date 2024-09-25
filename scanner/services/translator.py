import openai  # Import OpenAI library for interacting with OpenAI's API
import os
from dotenv import load_dotenv  # Import dotenv to load environment variables

# Load environment variables from the .env file
load_dotenv()
openai.api_key = os.getenv("OPENAI_API_KEY")  # Set OpenAI API key from environment variables

# Define the translation function
def translate(text, source_lang="en", target_lang="vi"):
    # Prepare the messages for the OpenAI API request
    messages = [
        {"role": "system", "content": "You are a helpful assistant that translates text."},
        {"role": "user", "content": f"Translate the following text from {source_lang} to {target_lang}: {text}"}
    ]
    
    # Send a request to the OpenAI API for translation
    response = openai.ChatCompletion.create(
        model="gpt-4",  # Specify the model to use (e.g., gpt-4 or gpt-3.5-turbo)
        messages=messages,
        max_tokens=1000,  # Limit the maximum number of tokens in the response
        temperature=0.3,  # Set the temperature for the response (controls randomness)
        n=1  # Number of response completions to generate
    )

    # Extract the translation from the response
    translation = response['choices'][0]['message']['content'].strip()
    return translation  # Return the translated text
