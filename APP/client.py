from flask import Flask, render_template, request, redirect, session
import requests
from Crypto.Cipher import AES
import json

app = Flask(__name__)
app.secret_key = '1234'

@app.route('/')
def index():
    return 'Aplicación simulación de Kerberos'

@app.route('/services', methods=['GET','POST'])
def service():
    if request.method == 'POST':
        service = request.form['service']
        session["service"] = service
        return redirect("/login")
    return render_template('services.html')


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        service = session.get('service')
        userIP = request.remote_addr
        lifetime = 60

        data = {
            "username": username,
            "service": service,
            "userIP": userIP,
            "lifetime": lifetime,
        }

        json_data = json.dumps(data)

        # Send the JSON data to port 5001 and endpoint /request
        url = "http://localhost:5001/as_request"
        headers = {"Content-Type": "application/json"}
        response = requests.post(url, json=json_data, headers=headers)

        # Check the response status code
        if response.status_code == 200:
            return "Authentication successful"
        else:
            return "Failed to send JSON data"
    return render_template("login.html")


if __name__ == '__main__':
    app.run(port=5000)
