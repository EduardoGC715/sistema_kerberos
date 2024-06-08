from flask import Flask, request, jsonify
from utils import AES
import database.Database as Database
import base64
from utils.Secrets import Secrets
import json
from datetime import datetime, timedelta

database = Database.Database()

app = Flask(__name__)

@app.route('/tgs_request', methods=['POST'])
def tgs_request():
    # Get the request data
    data = request.get_json()

    message  = data["message"]
    json_message = json.loads(message[0])
    service_principal = json_message["service_principal"]
    authenticator = message[1]
    tgt = message[2]

    service = database.service_exists_by_principal(service_principal)

    if service:
        service_data = service[0].to_dict()
        service_key = service_data["key"]

        tgt_cipher_text = tgt[0].encode('utf-8')
        tgt_nonce = tgt[1].encode('utf-8')
        tgt_tag = tgt[2].encode('utf-8')

        tgt_cipher_text = base64.b64decode(tgt_cipher_text)
        tgt_nonce = base64.b64decode(tgt_nonce)
        tgt_tag = base64.b64decode(tgt_tag)

        tgt_plain_text = AES.decrypt(tgt_cipher_text, Secrets.TGS_KEY.value, tgt_nonce, tgt_tag)
        #could be a new function here (extractMessage or somehting) TODO
        if tgt_plain_text:
            tgt_plain_text.decode("utf-8")
            tgt_plain_text = json.loads(tgt_plain_text)

            tgs_session_key = tgt_plain_text["tgs_session_key"]
            tgs_session_key.encode("utf-8")
            tgs_session_key = base64.b64decode(tgs_session_key)

            authenticator_cipher_text = authenticator[0].encode('utf-8')
            authenticator_nonce = authenticator[1].encode('utf-8')
            authenticator_tag = authenticator[2].encode('utf-8')

            authenticator_cipher_text = base64.b64decode(authenticator_cipher_text)
            authenticator_nonce = base64.b64decode(authenticator_nonce)
            authenticator_tag = base64.b64decode(authenticator_tag)

            authenticator_plain_text = AES.decrypt(authenticator_cipher_text, tgs_session_key, authenticator_nonce, authenticator_tag)

            if authenticator_plain_text:
                authenticator_plain_text.decode("utf-8")
                authenticator_plain_text = json.loads(authenticator_plain_text)
                if authenticator_plain_text["user_principal"] == tgt_plain_text["user_principal"]:
                    if abs(datetime.fromisoformat(authenticator_plain_text["timestamp"]) - datetime.fromisoformat(tgt_plain_text["timestamp"])) <= timedelta(minutes=2):
                        return "hola"

                    return jsonify({'message': 'Validation timeout'}), 507
                return jsonify({'message': 'User validation failed'}), 506
        return jsonify({'message': 'Error decrypting'}), 505

    # Prepare the response
    response = {
        'message': 'Request received successfully',
        'data': data
    }

    # Return the response as JSON
    return jsonify(response), 200

if __name__ == '__main__':
    app.run(port=5002)