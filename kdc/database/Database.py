from google.cloud import firestore
from google.oauth2 import service_account

class Database:
    credentials = service_account.Credentials.from_service_account_file(
        'kdc/database/proyecto-2-cg-firebase-adminsdk-gox8h-999ddeef4f.json')

    db = firestore.Client(project="proyecto-2-cg", credentials=credentials)

    def user_exists_by_principal(self, principal):
        users_ref = self.db.collection('users')
        doc = users_ref.where(field_path='principal', op_string='==', value=principal).get()
        
        if doc:
            return doc

        print(f"User with name {principal} does not exist in the database.")
        return False

    def service_exists_by_principal(self, principal):
        services_ref = self.db.collection('services')
        doc = services_ref.where(field_path='principal', op_string='==', value=principal).get()

        if doc:
            return doc

        print(f"Service with name {principal} does not exist in the database.")
        return False

    def save_user(self, user):
        users_ref = self.db.collection('users')
        users_ref.add(user)

    def save_service(self, service):
        services_ref = self.db.collection('services')
        services_ref.add(service)
