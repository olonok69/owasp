import os
from dotenv import load_dotenv, find_dotenv


def load_env():
    _ = load_dotenv(find_dotenv())


def get_openai_api_key():
    load_env()
    return os.getenv("OPENAI_API_KEY")


def get_serper_api_key():
    load_env()
    return os.getenv("SERPER_API_KEY")
