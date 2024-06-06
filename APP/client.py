from flask import Flask, render_template, request, redirect, g

app = Flask(__name__)

@app.route('/')
def index():
    return 'Aplicación simulación de Kerberos'

@app.route('/service', methods=['GET','POST'])
def service():
    if request.method == 'POST':
        service = request.form['service']
        g.service = service
        return redirect("/login")
    return render_template('service.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        service = g.get("service")
        userIP = request.remote_addr
        lifetime = 10
        return 'Authentication successful'
    return render_template('login.html')

if __name__ == '__main__':
    app.run()