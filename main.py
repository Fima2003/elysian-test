import json
from flask import Flask, request
from flask_cors import CORS
from db import find_user, compare_passwords
import requests
app = Flask(__name__)
CORS(app, origins=["http://localhost:5173"], supports_credentials=True)

@app.route('/')
def hello_world():
    return 'Hello, World!'

@app.route('/api/login', methods=['POST'])
def log_in():
    data = request.get_json()
    email = data.get('email')
    pswd = data.get('password')

    if not email or not pswd:
        return { "message": "Invalid data. Provide both email and password" }, 400
    
    user = find_user(email)
    
    if not user:
        return { "message": "User was not found" }, 404
    
    if not compare_passwords(user, pswd):
        return { "message": "Incorrect Password" }, 401

    try:
        response = requests.get('http://127.0.0.1:3000/get-intro')
        response.raise_for_status()
        output = response.json().get('output')
        return { "message": "Login successful", "output": output }, 200
    except requests.exceptions.RequestException as e:
        return { "message": f"Could not get intro: {e}" }, 503


if __name__ == "__main__":
    app.run(host='127.0.0.1', port=5000, debug=True)