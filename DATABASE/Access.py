from google.cloud import firestore
from google.oauth2 import service_account

credentials = service_account.Credentials.from_service_account_file(
    'DATABASE/proyecto-2-cg-firebase-adminsdk-gox8h-999ddeef4f.json')

db = firestore.Client(project="proyecto-2-cg", credentials=credentials)

users_ref = db.collection("services")
docs = users_ref.stream()

for doc in docs:
    print(f"{doc.id} => {doc.to_dict()}")
