from flask import Flask, request, jsonify
from pymongo import MongoClient
from cryptography.fernet import Fernet
import firebase_admin
from firebase_admin import credentials, auth
from bson.objectid import ObjectId
from flask_cors import CORS
from dotenv import load_dotenv
import os

app = Flask(__name__)

# Initialize CORS with specific origin and methods
CORS(app, resources={r"/*": {
    "origins": "*",
    "methods": ["GET", "POST", "DELETE", "OPTIONS"],
    "allow_headers": ["Content-Type", "Authorization"]
}})

# Firebase setup
cred = credentials.Certificate('/etc/secrets/firebase_credentials.json')
firebase_admin.initialize_app(cred)
load_dotenv()

# MongoDB setup
client = MongoClient(os.getenv('URL'))
db = client["password_manager"]
collection = db["passwords"]

key = os.getenv('ENCRYPTION_KEY')
cipher_suite = Fernet(key)

@app.route('/add_password', methods=['POST'])
def add_password():
    data = request.json
    encrypted_password = cipher_suite.encrypt(data['password'].encode())
    collection.insert_one({
        'website': data['website'],
        'username': data['username'],
        'password': encrypted_password,
        'user_id': data['user_id']
    })
    return jsonify({"message": "Password added successfully!"})

@app.route('/get_passwords/<user_id>', methods=['GET'])
def get_passwords(user_id):
    passwords = collection.find({"user_id": user_id})
    result = []
    for pwd in passwords:
        try:
            decrypted_password = cipher_suite.decrypt(pwd['password']).decode()
        except Exception as e:
            decrypted_password = "Error: Could not decrypt"
            print(f"Error decrypting password for {pwd['website']}: {e}")
        result.append({
            '_id': str(pwd['_id']),
            'website': pwd['website'],
            'username': pwd['username'],
            'password': decrypted_password
        })
    return jsonify(result)

@app.route('/delete_password', methods=['DELETE'])
def delete_password():
    data = request.json
    collection.delete_one({"_id": ObjectId(data['id'])})
    return jsonify({"message": "Password deleted successfully!"})

# Handle OPTIONS requests manually (if needed)
@app.route('/delete_password', methods=['OPTIONS'])
def handle_options():
    response = jsonify({'message': 'CORS preflight request successful'})
    response.headers.add('Access-Control-Allow-Origin', '*')
    response.headers.add('Access-Control-Allow-Methods', 'GET, POST, OPTIONS, DELETE')
    response.headers.add('Access-Control-Allow-Headers', 'Content-Type')
    return response

if __name__ == '__main__':
    app.run(debug=True)
