from flask import Flask, request, jsonify
from aps_secrets.Secrets import Secrets
from utils import AES
from datetime import datetime, timedelta
import base64
import json
import rsa

cache = {}

app = Flask(__name__)

@app.route('/aps_request', methods=['POST'])
def aps_request():
    # Get the request data
    data = request.get_json()

    # extract the data from the request
    message = data['message']
    authenticator = message[0]
    service_ticket = message[1]
    service = json.loads(message[2])["service_principal"]

    SERVICE_KEY = service_key_selector(service)

    # decrypt the service ticket
    decoded_service_ticket = decode_ciphertext_nonce_tag(service_ticket)
    service_ticket_plain_text = AES.decrypt(decoded_service_ticket[0], SERVICE_KEY, decoded_service_ticket[1], decoded_service_ticket[2])

    # check if decryption was successful
    if service_ticket_plain_text:
        # extract the information from the service ticket
        service_ticket_plain_text.decode("utf-8")
        service_ticket_plain_text = json.loads(service_ticket_plain_text)

        # extract the service session key
        service_session_key = service_ticket_plain_text["service_session_key"]
        service_session_key.encode("utf-8")
        service_session_key = base64.b64decode(service_session_key)

        # decrypt the authenticator
        decoded_authenticator = decode_ciphertext_nonce_tag(authenticator)
        authenticator_plain_text = AES.decrypt(decoded_authenticator[0], service_session_key, decoded_authenticator[1], decoded_authenticator[2])

        # check if decryption was successful
        if authenticator_plain_text:
            # extract the information from the authenticator
            authenticator_plain_text.decode("utf-8")
            authenticator_plain_text = json.loads(authenticator_plain_text)

            # validate the user principal from the authenticator and the service ticket
            if authenticator_plain_text["user_principal"] == service_ticket_plain_text["user_principal"]:
                if abs(datetime.fromisoformat(authenticator_plain_text["timestamp"]) - datetime.fromisoformat(service_ticket_plain_text["timestamp"])) <= timedelta(minutes=2):
                    if datetime.strptime(service_ticket_plain_text["lifetime"], "%Y-%m-%d %H:%M:%S") > datetime.now():
                        # TODO validate ip
                        try:
                            # check if the user is already in the cache
                            cache[authenticator_plain_text["user_principal"]]
                            return jsonify({"message": "User already in cache"}), 508
                        except KeyError:
                            # if the user is not in the cache, add it
                            cache[authenticator_plain_text["user_principal"]] = authenticator_plain_text["timestamp"]
                            # create the response
                            service_authenticator = {
                                "service_principal": service_ticket_plain_text["service_principal"],
                                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                                "service_action": service_action(service_ticket_plain_text["service_principal"])
                            }

                            # encrypt the service authenticator
                            encrypted_service_authenticator = AES.encrypt(json.dumps(service_authenticator).encode("utf-8"), service_session_key)

                            # encode the encrypted service authenticator for json response
                            encoded_service_authenticator = encode_ciphertext_nonce_tag(encrypted_service_authenticator)

                            # delete the user from the cache
                            del cache[authenticator_plain_text["user_principal"]]

                            # return the service authenticator
                            return jsonify({'message': encoded_service_authenticator}), 200
                return jsonify({"message": "Validation timeout"}), 507
            return jsonify({'message': 'User validation failed'}), 506
    return jsonify({'message': 'Error decrypting'}), 505

@app.route('/aps_key_request', methods=['GET'])
def aps_key_request():
    # get the data from request
    data = request.get_json()
    service = data['service_principal']

    # get the service key
    SERVICE_KEY = service_key_selector(service)

    # get the tgs public key
    with open('aps/aps_secrets/tgs_public.pem', 'rb') as f:
        TGS_PUBLIC_KEY = rsa.PublicKey.load_pkcs1(f.read())

    # encrypt the aps key with the as public key
    encrypted_aps_key = rsa.encrypt(SERVICE_KEY, TGS_PUBLIC_KEY)

    # encode the encrypted tgs key for json response
    encoded_aps_key = base64.b64encode(encrypted_aps_key).decode('utf-8')

    # return the encrypted tgs key
    return jsonify({'message': encoded_aps_key}), 200

def service_key_selector(service):
    # select the service
    if service == "service1@TEC":
        return Secrets.service1.value
    elif service == "service2@TEC":
        return Secrets.service2.value
    elif service == "service3@TEC":
        return Secrets.service3.value
    else:
        return None

def service_action(service):
    # select the service
    if service == "service1@TEC":
        return "service1_action"
    elif service == "service2@TEC":
        return "service2_action"
    elif service == "service3@TEC":
        return "service3_action"
    else:
        return None

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
    app.run(port=5003)