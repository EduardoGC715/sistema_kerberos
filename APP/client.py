from flask import Flask, render_template, request, redirect, session
import requests
from utils import AES
from datetime import datetime
import json
import hashlib
import base64

app = Flask(__name__)
app.secret_key = '1234'
current_realm = '@TEC'

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
        lifetime =  600 # minutes defined by default by app.

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
        principal = username + current_realm
        service = session.get('service')
        message = as_rep["message"][0]
        tgt = as_rep["message"][1]

        # create the user key using the password and the principal
        user_key = password + principal
        user_hashed_key = hashlib.sha256(user_key.encode("utf-8")).digest()

        # decrypt the message
        decoded_message = decode_ciphertext_nonce_tag(message)
        message_plain_text = AES.decrypt(decoded_message[0], user_hashed_key, decoded_message[1], decoded_message[2])

        if message_plain_text:
            # extract the information from the message
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

            # Send the JSON data to ticket granting server
            url = "http://localhost:5002/tgs_request"
            headers = {"Content-Type": "application/json"}
            response = requests.post(url, json=tgs_message, headers=headers)

            return "Authentication successful!"

        return redirect("/loginPassword")
    return render_template("loginPassword.html")

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
