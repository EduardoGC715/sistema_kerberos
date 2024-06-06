from flask import Flask, request, jsonify
from Crypto.Cipher import AES

app = Flask(__name__)

def encrypt(msg, key):
    # Create an AES cipher object with the key using the mode EAX
    cipher = AES.new(key, AES.MODE_EAX)
    nonce = cipher.nonce

    # Encrypt the message
    ciphertext, tag = cipher.encrypt_and_digest(msg.encode('utf-8'))

    return nonce, ciphertext, tag

@app.route('/as_request', methods=['POST'])
def as_request():
    # Get the request data
    data = request.get_json()
    print(data)

    # Prepare the response
    response = {
        'message': 'Request received successfully',
        'data': data
    }

    # Return the response as JSON
    return jsonify(response), 200

if __name__ == '__main__':
    app.run(port=5001)