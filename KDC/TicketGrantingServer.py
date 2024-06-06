from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route('/request', methods=['POST'])
def request():
    # Get the request data
    data = request.get_json()

    # Process the request data
    # ...

    # Prepare the response
    response = {
        'message': 'Request received successfully',
        'data': data
    }

    # Return the response as JSON
    return jsonify(response), 200

@app.route('/response', methods=['GET'])
def response():
    # Prepare the response
    response = {
        'message': 'This is a sample response'
    }

    # Return the response as JSON
    return jsonify(response), 200

if __name__ == '__main__':
    app.run()