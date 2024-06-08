from datetime import datetime
from dateutil.relativedelta import relativedelta
import kdc.database.Database as Database
import hashlib

database = Database.Database()

def create_key(msg):
    # Create a new AES key
    key = hashlib.sha256(msg.encode("utf-8")).digest()
    return key

def add_user():
    user_name = input("Enter username: ")
    realm = input("Enter realm: ")
    password = input("Enter password: ")
    ticket_validity_duration = int(
        input("Enter ticket validity duration (in minutes): ")
    )
    principal = "{}@{}".format(user_name, realm)
    key = create_key(password + principal)
    user = {
        "principal": principal,
        "key": key,
        "knov": 1,
        "ticket_validity_duration": ticket_validity_duration,
        "ticket_renewal_limit": 5,
        "password_expiration_date": datetime.now() + relativedelta(months=6),
        "principal_expiration_date": datetime.now() + relativedelta(months=12),
    }
    database.save_user(user)

def add_service():
    service_name = input("Enter service name: ")
    realm = input("Enter service realm: ")
    password = input("Enter service password: ")
    key = create_key(password + service_name + realm)
    principal = "{}@{}".format(service_name, realm)
    service = {
        "principal": principal,
        "key": key,
        "knov": 1,
        "password_expiration_date": datetime.now() + relativedelta(months=6),
        "principal_expiration_date": datetime.now() + relativedelta(months=12),
    }
    database.save_service(service)

#==========MAIN==========#
add_user()
add_user()
# add_service()