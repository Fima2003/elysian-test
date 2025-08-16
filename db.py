import bcrypt
from pymongo import MongoClient

from constants import MONGO_URI

client = MongoClient(MONGO_URI)
db = client["elysian_db"] 

def find_user(email: str):
	try:
		users = db.get_collection('users')
		return users.find_one({"email": email})
	except Exception as e:
		return False

def compare_passwords(user, pswd: str):
	if bcrypt.checkpw(pswd.encode('utf-8'), user['password'].encode('utf-8')):
		return True
	else:
		return False