import os
from dotenv import load_dotenv
load_dotenv()

MONGO_URI = os.getenv('MONGO_URI')
NODE_URI = os.getenv('NODE_URI', 'http://127.0.0.1:3000')