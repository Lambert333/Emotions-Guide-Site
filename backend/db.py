import firebase_admin
from firebase_admin import credentials
from firebase_admin import db

# Укажите путь к файлу с ключом и URL вашей Realtime Database
cred = credentials.Certificate('creds.json')
firebase_admin.initialize_app(cred, {
    'databaseURL': 'https://emotions-guide-c173c-default-rtdb.europe-west1.firebasedatabase.app/'
})

# Ссылка на нужный узел в базе данных
ref = db.reference('/Users')

# Пример чтения данных
data = ref.get()
print(data)
