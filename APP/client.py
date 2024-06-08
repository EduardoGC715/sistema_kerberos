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
        username = request.form["username"]
        service = session.get('service')
        userIP = request.remote_addr
        lifetime = 60

        data = {
            "user_principal": username + current_realm,
            "service_principal": service + current_realm,
            "userIP": userIP,
            "lifetime": lifetime
        }

        # Send the JSON data to port 5001 and endpoint /as_request
        url = "http://localhost:5001/as_request"
        headers = {"Content-Type": "application/json"}
        response = requests.post(url, json=data, headers=headers)
        # Check the response status code
        if response.status_code == 200:
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
        password = request.form["password"]
        as_rep = session.get('as_rep')
        username = session.get('username')
        principal = username + current_realm
        service = session.get('service')

        message = as_rep["message"][0]
        tgt = as_rep["message"][1]
        user_key = password + principal
        user_hashed_key = hashlib.sha256(user_key.encode("utf-8")).digest()

        message_cipher_text = message[0].encode("utf-8")
        message_nonce = message[1].encode("utf-8")
        message_tag = message[2].encode("utf-8")

        message_cipher_text = base64.b64decode(message_cipher_text)
        message_nonce = base64.b64decode(message_nonce)
        message_tag = base64.b64decode(message_tag)

        message_plain_text = AES.decrypt(message_cipher_text, user_hashed_key, message_nonce, message_tag)

        if message_plain_text:
            message_plain_text.decode("utf-8")
            message_plain_text = json.loads(message_plain_text)

            new_message = json.dumps({
                "service_principal": service + current_realm,
                "lifetime": 600
            })
            new_authenticator = json.dumps({
                "user_principal": principal,
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            })

            tgs_session_key = message_plain_text["tgs_session_key"]
            tgs_session_key.encode("utf-8")
            tgs_session_key = base64.b64decode(tgs_session_key)

            authenticator = AES.encrypt(new_authenticator.encode("utf-8"), tgs_session_key)

            values_authenticator = [
                base64.b64encode(authenticator[0]).decode('utf-8'), # cipher_text
                base64.b64encode(authenticator[1]).decode('utf-8'), # nonce
                base64.b64encode(authenticator[2]).decode('utf-8') # tag
            ]

            data = {
                "message": [new_message, values_authenticator, tgt]
            }

            url = "http://localhost:5002/tgs_request"
            headers = {"Content-Type": "application/json"}
            response = requests.post(url, json=data, headers=headers)

            return "Authentication successful!"

        return redirect("/loginPassword")
    return render_template("loginPassword.html")

if __name__ == '__main__':
    app.run(port=5000)
