from flask import Flask, request, jsonify
from Crypto.Cipher import AES

app = Flask(__name__)

@app.route('/tgs_request', methods=['POST'])
def tgs_request():
    # Get the request data
    data = request.get_json()

    print(data)

    # Process the request data
    # ...

    # Prepare the response
    response = {
        'message': 'Request received successfully',
        'data': data
    }

    # Return the response as JSON
    return jsonify(response), 200

if __name__ == '__main__':
    app.run(port=5002)