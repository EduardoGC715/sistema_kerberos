from flask import Flask, request, jsonify
import json
from datetime import datetime
import database.Database as Database
from utils.Secrets import Secrets
import base64
from utils import AES

database = Database.Database()

app = Flask(__name__)

@app.route('/as_request', methods=['POST'])
def as_request():
    # Get the request data
    data = request.get_json()
    user = database.user_exists_by_principal(data['user_principal'])
    user_data = user[0].to_dict()
    lifetime = min(data["lifetime"], user_data["ticket_validity_duration"])

    if user:
        message = json.dumps({
            "tgs_id": Secrets.TGS_ID.value,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "lifetime": lifetime,
            "tgs_session_key": base64.b64encode(Secrets.TGS_SESSION_KEY.value).decode('utf-8')
            })
        tgt = json.dumps({
            "user_principal": data["user_principal"],
            "tgs_id": Secrets.TGS_ID.value,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "userIP": data["userIP"],
            "tgt_lifetime": 5,
            "tgs_session_key": base64.b64encode(Secrets.TGS_SESSION_KEY.value).decode('utf-8')
            })
        encrypted_message = AES.encrypt(message.encode("utf-8"), user_data["key"])
        encrypted_tgt = AES.encrypt(tgt.encode("utf-8"), Secrets.TGS_KEY.value)

        values_message = [
                        base64.b64encode(encrypted_message[0]).decode('utf-8'),
                        base64.b64encode(encrypted_message[1]).decode('utf-8'),
                        base64.b64encode(encrypted_message[2]).decode('utf-8')
                    ]
        values_tgt = [
                        base64.b64encode(encrypted_tgt[0]).decode('utf-8'),
                        base64.b64encode(encrypted_tgt[1]).decode('utf-8'),
                        base64.b64encode(encrypted_tgt[2]).decode('utf-8')
                    ]
        
        return jsonify({'message': [values_message, values_tgt ]}), 200
    
    return jsonify({'message': 'User does not exist'}), 404

if __name__ == '__main__':
    app.run(port=5001)