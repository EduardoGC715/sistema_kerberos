from flask import Flask, request, jsonify
import json
from datetime import datetime, timedelta
import database.Database as Database
from secrets import token_bytes
from as_secrets.Secrets import Secrets
import base64
from utils import AES
import rsa
import requests

database = Database.Database()

app = Flask(__name__)

@app.route('/as_request', methods=['POST'])
def as_request():
    # Get the request data
    data = request.get_json()
    user = database.user_exists_by_principal(data['user_principal'])
    user_data = user[0].to_dict()
    lifetime = min(data["lifetime"], user_data["ticket_validity_duration"])
    session_key = token_bytes(32)
    
    # ask for the tgs key
    TGS_KEY = get_tgs_key()
    
    # Check if the user exists
    if user:
        #create the message reponse
        message = json.dumps({
            "tgs_id": Secrets.TGS_ID.value,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "lifetime": lifetime,
            "tgs_session_key": base64.b64encode(session_key).decode('utf-8')
            })
        
        # create the ticket granting ticket
        tgt = json.dumps({
            "user_principal": data["user_principal"],
            "tgs_id": Secrets.TGS_ID.value,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "userIP": data["userIP"],
            "tgt_lifetime": (datetime.now() + timedelta(minutes=5)).strftime("%Y-%m-%d %H:%M:%S"),
            "tgs_session_key": base64.b64encode(session_key).decode('utf-8')
            })
        
        # encrypt the message and the tgt
        encrypted_message = AES.encrypt(message.encode("utf-8"), user_data["key"])
        encrypted_tgt = AES.encrypt(tgt.encode("utf-8"), TGS_KEY)

        # encode the encrypted message and tgt for json response
        encoded_message = encode_ciphertext_nonce_tag(encrypted_message)
        encoded_tgt = encode_ciphertext_nonce_tag(encrypted_tgt)
        
        return jsonify({'message': [encoded_message, encoded_tgt ]}), 200
    
    return jsonify({'message': 'User does not exist'}), 404

def get_tgs_key():
    url = "http://localhost:5002/tgs_key_request"
    headers = {"Content-Type": "application/json"}
    response = requests.get(url, headers=headers)
    response = response.json()["message"]

    # get the as private key
    with open('kdc/as_secrets/as_private.pem', 'rb') as f:
        as_private_key = rsa.PrivateKey.load_pkcs1(f.read())
    
    #decode the tgs key
    response = base64.b64decode(response.encode('utf-8'))
    tgs_key = rsa.decrypt(response, as_private_key)

    return tgs_key

def encode_ciphertext_nonce_tag(message):
    # encode the message for json response
    return [
        base64.b64encode(message[0]).decode('utf-8'),
        base64.b64encode(message[1]).decode('utf-8'),
        base64.b64encode(message[2]).decode('utf-8')
    ]

if __name__ == '__main__':
    app.run(port=5001)