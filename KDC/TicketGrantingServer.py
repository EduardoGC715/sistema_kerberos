from flask import Flask, request, jsonify
from utils import AES
import database.Database as Database
import base64
from tgs_secrets.Secrets import Secrets
import json
from datetime import datetime, timedelta
from secrets import token_bytes
import rsa
import requests

database = Database.Database()
cache = {}
TGS_KEY = Secrets.TGS_KEY.value

app = Flask(__name__)

@app.route('/tgs_request', methods=['POST'])
def tgs_request():
    # Get the request data
    data = request.get_json()

    # extract the data from the request
    message  = data["message"]
    json_message = json.loads(message[0])
    service_principal = json_message["service_principal"]
    authenticator = message[1]
    tgt = message[2] # Ticket Granting Ticket

    # check if the service exists in the database
    service = database.service_exists_by_principal(service_principal)
    if service:
        # get the service key
        service_key = get_service_key(service_principal)

        # decrypt the tgt
        decoded_tgt = decode_ciphertext_nonce_tag(tgt)
        tgt_plain_text = AES.decrypt(decoded_tgt[0], TGS_KEY, decoded_tgt[1], decoded_tgt[2])

        # check if decryption was successful
        if tgt_plain_text:
            # extract the information from the tgt
            tgt_plain_text.decode("utf-8")
            tgt_plain_text = json.loads(tgt_plain_text)
            
            # extract the TGS session key
            tgs_session_key = tgt_plain_text["tgs_session_key"]
            tgs_session_key.encode("utf-8")
            tgs_session_key = base64.b64decode(tgs_session_key)
            
            # decrypt the authenticator
            decoded_authenticator = decode_ciphertext_nonce_tag(authenticator)
            authenticator_plain_text = AES.decrypt(decoded_authenticator[0], tgs_session_key, decoded_authenticator[1], decoded_authenticator[2])

            # check if decryption was successful
            if authenticator_plain_text:
                # extract the information from the authenticator
                authenticator_plain_text.decode("utf-8")
                authenticator_plain_text = json.loads(authenticator_plain_text)

                # validate the user principal from the authenticator and the tgt
                if authenticator_plain_text["user_principal"] == tgt_plain_text["user_principal"]:
                    # validate the timestamp from the authenticator and the tgt, should be within 2 minutes
                    if abs(datetime.fromisoformat(authenticator_plain_text["timestamp"]) - datetime.fromisoformat(tgt_plain_text["timestamp"])) <= timedelta(minutes=2):
                        # validate the lifetime of the tgt is still valid
                        if datetime.strptime(tgt_plain_text["tgt_lifetime"], "%Y-%m-%d %H:%M:%S") > datetime.now():
                            # TODO validate ip                            # check if the user is already in the cache
                            try:
                                # check if the user is already in the cache
                                cache[authenticator_plain_text["user_principal"]]
                                return jsonify({'message': 'User already in cache'}), 508
                            except KeyError:
                                # if the user is not in the cache, add it
                                cache[authenticator_plain_text["user_principal"]] = authenticator_plain_text["timestamp"]
                                
                                # create a new service session key
                                service_session_key = token_bytes(32)
                                # create the new message
                                new_message = json.dumps({
                                    "service_principal": service_principal,
                                    "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                                    "lifetime": tgt_plain_text["tgt_lifetime"],
                                    "service_session_key": base64.b64encode(service_session_key).decode('utf-8')
                                })

                                # create the new service ticket
                                service_ticket = json.dumps({
                                    "user_principal": authenticator_plain_text["user_principal"],
                                    "service_principal": service_principal,
                                    "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                                    "userIP": tgt_plain_text["userIP"], #TODO validate time of service ???
                                    "lifetime": (datetime.now() + timedelta(minutes=600)).strftime("%Y-%m-%d %H:%M:%S"),
                                    "service_session_key": base64.b64encode(service_session_key).decode('utf-8')
                                })

                                # encrypt the new message with the TGS session key
                                encrypted_message = AES.encrypt(new_message.encode("utf-8"), tgs_session_key)

                                # encrypt the service ticket with the service key
                                encrypted_service_ticket = AES.encrypt(service_ticket.encode("utf-8"), service_key)

                                # encode the encrypted message and service ticket for json response
                                encoded_message = encode_ciphertext_nonce_tag(encrypted_message)
                                encoded_service_ticket = encode_ciphertext_nonce_tag(encrypted_service_ticket)

                                # delete the user from the cache
                                del cache[authenticator_plain_text["user_principal"]]
                                
                                # return the new message and the service ticket
                                return jsonify({'message': [encoded_message, encoded_service_ticket]}), 200
                    return jsonify({'message': 'Validation timeout'}), 507
                return jsonify({'message': 'User validation failed'}), 506
        return jsonify({'message': 'Error decrypting'}), 505
    return jsonify({'message': 'Service not found'}), 404

@app.route('/tgs_key_request', methods=['GET'])
def tgs_key_request():
    # get the as public key
    with open('kdc/tgs_secrets/as_public.pem', 'rb') as f:
        AS_PUBLIC_KEY = rsa.PublicKey.load_pkcs1(f.read())
    
    # encrypt the tgs key with the as public key
    encrypted_tgs_key = rsa.encrypt(Secrets.TGS_KEY.value, AS_PUBLIC_KEY)

    # encode the encrypted tgs key for json response
    encoded_tgs_key = base64.b64encode(encrypted_tgs_key).decode('utf-8')

    # return the encrypted tgs key
    return jsonify({'message': encoded_tgs_key}), 200

def get_service_key(service_principal):
    url = "http://localhost:5003/aps_key_request"
    headers = {"Content-Type": "application/json"}

    response = requests.get(url, json={"service_principal": service_principal}, headers=headers)
    response = response.json()["message"]

    # get the tgs private key
    with open('kdc/tgs_secrets/tgs_private.pem', 'rb') as f:
        tgs_private_key = rsa.PrivateKey.load_pkcs1(f.read())

    # decode the aps key
    response = base64.b64decode(response.encode('utf-8'))
    aps_key = rsa.decrypt(response, tgs_private_key)

    return aps_key

def decode_ciphertext_nonce_tag(message):
    # decode the message for json response
    return [
        base64.b64decode(message[0].encode('utf-8')),
        base64.b64decode(message[1].encode('utf-8')),
        base64.b64decode(message[2].encode('utf-8'))
    ]

def encode_ciphertext_nonce_tag(message):
    # encode the message for json response
    return [
        base64.b64encode(message[0]).decode('utf-8'),
        base64.b64encode(message[1]).decode('utf-8'),
        base64.b64encode(message[2]).decode('utf-8')
    ]

if __name__ == '__main__':
    app.run(port=5002)