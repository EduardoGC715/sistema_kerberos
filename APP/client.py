from flask import Flask, render_template, request, redirect, session, jsonify
import requests
from utils import AES
from datetime import datetime, timedelta
import json
import hashlib
import base64
from app_secrets.Secrets import Secrets

app = Flask(__name__)
app.secret_key = Secrets.APP_KEY.value
current_realm = '@TEC'

cache = {}

@app.route('/')
def index():
    return 'Aplicación simulación de Kerberos'

@app.route('/services', methods=['GET','POST'])
def services():
    if request.method == 'POST':
        service = request.form['service']
        session["service"] = service
        return redirect("/loginUser")
    return render_template('services.html')


@app.route("/loginUser", methods=["GET", "POST"])
def loginUser():
    if request.method == "POST":
        # Get the data to create message
        username = request.form["username"]
        service = session.get('service')
        userIP = request.remote_addr
        lifetime =  600

        # create the message for request
        message = {
            "user_principal": username + current_realm,
            "service_principal": service + current_realm,
            "userIP": userIP,
            "lifetime": lifetime
        }

        # Send the JSON data to port 5001 and endpoint /as_request
        url = "http://localhost:5001/as_request"
        headers = {"Content-Type": "application/json"}
        response = requests.post(url, json=message, headers=headers)

        # Check the response status code
        if response.status_code == 200:
            # save data for next response and redirect
            as_rep = response.json()
            session["as_rep"] = as_rep
            session["username"] = username
            return redirect("/loginPassword")
        
        if response.status_code == 404:
            return "Invalid user"
        else:
            return "Failed to send JSON data"
    return render_template("loginUser.html")

@app.route("/loginPassword", methods=["GET", "POST"])
def loginPassword():
    if request.method == "POST":
        # get the data to create message
        password = request.form["password"]
        as_rep = session.get('as_rep')
        username = session.get('username')
        service = session.get('service')
        principal = username + current_realm
        message = as_rep["message"][0]
        tgt = as_rep["message"][1]

        # create the user key using the password and the principal
        user_key = password + principal
        user_hashed_key = hashlib.sha256(user_key.encode("utf-8")).digest()

        # decrypt the message
        decoded_message = decode_ciphertext_nonce_tag(message)
        message_plain_text = AES.decrypt(decoded_message[0], user_hashed_key, decoded_message[1], decoded_message[2])

        # check if decryption was successful
        if message_plain_text:
            # decode the message
            message_plain_text.decode("utf-8")
            message_plain_text = json.loads(message_plain_text)

            # create the new message
            new_message = json.dumps({
                "service_principal": service + current_realm,
                "lifetime": 600
            })

            # create the new authenticator message
            new_authenticator = json.dumps({
                "user_principal": principal,
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            })

            # extract the tgt session key
            tgs_session_key = message_plain_text["tgs_session_key"]
            tgs_session_key.encode("utf-8")
            tgs_session_key = base64.b64decode(tgs_session_key)

            # encrypt the new authenticator message with the tgs session key
            authenticator = AES.encrypt(new_authenticator.encode("utf-8"), tgs_session_key)

            # encode the new message, the new authenticator and the tgt for json response
            values_authenticator = encode_ciphertext_nonce_tag(authenticator)

            # create the tgs message
            tgs_message = {
                "message": [new_message, values_authenticator, tgt]
            }

            # delete the as_rep data
            session.pop('as_rep', None)

            # Send the JSON data to ticket granting server
            url = "http://localhost:5002/tgs_request"
            headers = {"Content-Type": "application/json"}
            response = requests.post(url, json=tgs_message, headers=headers)

            # check the response status code
            if response.status_code == 200:
            # save data for next response and redirect
                tgs_rep = response.json()
                session["tgs_rep"] = tgs_rep
                session["tgs_session_key"] = tgs_session_key

                return redirect("/service")
    
            elif response.status_code == 404:
                return "Invalid service"
            else:
                return "Returned error: " + str(response.status_code)
        
    return render_template("loginPassword.html")

@app.route("/service", methods=["GET"])
def service():
    # get the data to create message
    tgs_rep = session.get('tgs_rep')
    tgs_session_key = session.get('tgs_session_key')
    service = session.get('service')
    username = session.get('username')
    principal = username + current_realm

    # extract the information from the tgs_rep
    message = tgs_rep["message"][0]
    service_ticket = tgs_rep["message"][1]

    # decode message
    decoded_message = decode_ciphertext_nonce_tag(message)

    # decrypt the message
    message_plain_text = AES.decrypt(decoded_message[0], tgs_session_key, decoded_message[1], decoded_message[2])
    
    # delete the tgs_session_key and tgs_rep data
    session.pop('tgs_session_key', None)
    session.pop("tgs_rep", None)

    # check if decryption was successful
    if message_plain_text:
        # decode the message
        message_plain_text.decode("utf-8")
        message_plain_text = json.loads(message_plain_text)

        # create the new authenticator
        new_authenticator = json.dumps({
            "user_principal": principal,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        })

        new_message = json.dumps({
            "service_principal": service + current_realm,
            "lifetime": 600
        })
        
        #extract the service session key
        service_session_key = message_plain_text["service_session_key"]
        service_session_key.encode("utf-8")
        service_session_key = base64.b64decode(service_session_key)

        # encrypt the new authenticator with the service session key
        authenticator = AES.encrypt(new_authenticator.encode("utf-8"), service_session_key)

        # encode the new authenticator for json response
        encoded_authenticator = encode_ciphertext_nonce_tag(authenticator)

        # create the service message
        service_message = {
            "message": [encoded_authenticator, service_ticket, new_message]
        }

        # delete the tgs_rep data
        session.pop('tgs_rep', None)

        # Send the JSON data to service
        url = "http://localhost:5003/aps_request"
        headers = {"Content-Type": "application/json"}
        response = requests.post(url, json=service_message, headers=headers)

        # check the response status code
        if response.status_code == 200:
            # extract the information from the response
            aps_rep = response.json()
            service_authenticator = aps_rep["message"]

            # decode the message
            decoded_service_authenticator = decode_ciphertext_nonce_tag(service_authenticator)

            # decrypt the message
            service_authenticator_plain_text = AES.decrypt(decoded_service_authenticator[0], service_session_key, decoded_service_authenticator[1], decoded_service_authenticator[2])
            
            # check if decryption was successful
            if service_authenticator_plain_text:
                # decode the message
                service_authenticator_plain_text.decode("utf-8")
                service_authenticator_plain_text = json.loads(service_authenticator_plain_text)
                
                # validate the user principal from the authenticator and the service ticket
                if (service + current_realm) == service_authenticator_plain_text["service_principal"]:
                    if abs(datetime.fromisoformat(service_authenticator_plain_text["timestamp"]) - datetime.now()) <= timedelta(minutes=2):
                        cache["service_ticket"] = service_ticket
                        return jsonify({'Service action': service_authenticator_plain_text["service_action"]})
                    return "Invalid timestamp"
                return "Error authenticating"
            else:
                return "Error decrypting"
    
        elif response.status_code == 404:
            return "Invalid service"
        else:
            return "Returned error: " + str(response.status_code)
    return jsonify({'message': 'Error decrypting'}), 505


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
    app.run(port=5000)
