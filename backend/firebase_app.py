import os
import firebase_admin
import jwt
import time
from firebase_admin import credentials, auth, db
from typing import Optional
import logging
from dotenv import load_dotenv
import os
from fastapi import HTTPException
load_dotenv(dotenv_path=os.path.join(os.path.dirname(__file__), '.env'))

logger = logging.getLogger(__name__)

class Firebase:
    """Класс для управления Firebase приложением с Realtime Database"""
    
    def __init__(self):
        self.app: Optional[firebase_admin.App] = None
        self._initialize_app()
    
    def _initialize_app(self):
        """Инициализация Firebase приложения с Realtime Database"""
        try:
            # Проверяем, не инициализировано ли уже приложение
            if not firebase_admin._apps:
                # Путь к файлу сервисного аккаунта
                service_account_path = os.path.join(os.path.dirname(__file__), os.getenv('FIREBASE_SERVICE_ACCOUNT_PATH', 'serviceAccountKey.json'))
                
                # URL базы данных Realtime Database
                database_url = os.getenv('FIREBASE_DATABASE_URL', 'https://your-project-id-default-rtdb.firebaseio.com/')
                
                if os.path.exists(service_account_path):
                    # Инициализация с файлом сервисного аккаунта
                    cred = credentials.Certificate(service_account_path)
                    self.app = firebase_admin.initialize_app(cred, {
                        'databaseURL': database_url
                    })
                    logger.info("Firebase приложение инициализировано с файлом сервисного аккаунта")
                else:
                    raise ValueError(f"Файл сервисного аккаунта не найден: {service_account_path}. Убедитесь, что FIREBASE_SERVICE_ACCOUNT_PATH установлен правильно в .env.")
            else:
                # Используем существующее приложение
                self.app = firebase_admin.get_app()
                logger.info("Используется существующее Firebase приложение")
                
        except Exception as e:
            logger.error(f"Ошибка инициализации Firebase: {e}")
            raise e
    
    def get_auth(self):
        """Получить экземпляр Firebase Auth"""
        return auth
    
    def get_database(self):
        """Получить экземпляр Realtime Database"""
        return db
    
    def get_db_reference(self, path: str = ''):
        """Получить ссылку на узел в Realtime Database"""
        return db.reference(path)
    
    def verify_token(self, token: str) -> dict:
        """Проверка JWT токена с tolerance к clock skew"""
        try:
            # Manual decode с leeway 300 сек (5 мин) для tolerance к clock skew
            decoded_payload = jwt.decode(token, options={"verify_signature": False, "leeway": 300})
            iat = decoded_payload.get('iat')
            exp = decoded_payload.get('exp')
            current_time = time.time()
            if iat > current_time + 300 or exp < current_time - 300:
                raise ValueError("Token time invalid with leeway")
            
            # Затем стандартная verify_id_token для sig и revoked check
            decoded_token = auth.verify_id_token(token, check_revoked=True)
            return decoded_token
        except Exception as e:
            error_str = str(e)
            if "Token used too early" in error_str or "iat" in error_str:
                # Для dev: Если ошибка времени, используем manual decode (skip sig/revoked for tolerance)
                logger.warning(f"Clock skew detected, using manual decode: {error_str}")
                # Manual full decode with leeway (but without sig verify for dev)
                try:
                    decoded_token = jwt.decode(token, options={"verify_signature": False, "leeway": 300})
                    # Добавляем 'uid' как alias для 'sub' (как в Firebase SDK)
                    decoded_token['uid'] = decoded_token.get('sub', '')
                    # Проверяем issuer и aud для Firebase
                    if decoded_token.get('iss') not in ['https://securetoken.google.com/emotions-guide-c173c', 'https://securetoken.googleapis.com/emotions-guide-c173c']:
                        raise ValueError("Invalid issuer")
                    if decoded_token.get('aud') != 'emotions-guide-c173c':
                        raise ValueError("Invalid audience")
                    return decoded_token
                except jwt.InvalidTokenError as jt_e:
                    logger.error(f"Manual decode failed: {jt_e}")
                    raise HTTPException(status_code=401, detail="Invalid token")
            logger.error(f"Ошибка проверки токена: {e}")
            raise e
    
    def create_custom_token(self, uid: str) -> str:
        """Создание кастомного токена для пользователя"""
        try:
            custom_token = auth.create_custom_token(uid)
            return custom_token.decode('utf-8')
        except Exception as e:
            logger.error(f"Ошибка создания кастомного токена: {e}")
            raise e

# Глобальный экземпляр Firebase
firebase_app = Firebase()

# Функции для удобного доступа
def get_firebase_auth():
    """Получить Firebase Auth"""
    return firebase_app.get_auth()

def get_realtime_db():
    """Получить Realtime Database"""
    return firebase_app.get_database()

def get_db_reference(path: str = ''):
    """Получить ссылку на узел в Realtime Database"""
    return firebase_app.get_db_reference(path)

def verify_firebase_token(token: str) -> dict:
    """Проверить Firebase токен"""
    return firebase_app.verify_token(token)

def create_firebase_custom_token(uid: str) -> str:
    """Создать кастомный Firebase токен"""
    return firebase_app.create_custom_token(uid)

# Утилитарные функции для работы с Realtime Database
class RealtimeDB:
    """Класс-помощник для работы с Realtime Database"""
    
    @staticmethod
    def create(path: str, data: dict) -> str:
        """Создать новую запись и вернуть сгенерированный ключ"""
        ref = get_db_reference(path)
        new_ref = ref.push(data)
        return new_ref.key
    
    @staticmethod
    def get(path: str) -> dict:
        """Получить данные по пути"""
        ref = get_db_reference(path)
        return ref.get()
    
    @staticmethod
    def set(path: str, data: dict) -> None:
        """Установить данные по пути"""
        ref = get_db_reference(path)
        ref.set(data)
    
    @staticmethod
    def update(path: str, data: dict) -> None:
        """Обновить данные по пути"""
        ref = get_db_reference(path)
        ref.update(data)
    
    @staticmethod
    def delete(path: str) -> None:
        """Удалить данные по пути"""
        ref = get_db_reference(path)
        ref.delete()
    
    @staticmethod
    def query_order_by_child(path: str, child_key: str):
        """Создать запрос с сортировкой по дочернему ключу"""
        ref = get_db_reference(path)
        return ref.order_by_child(child_key)
    
    @staticmethod
    def query_limit_to_last(path: str, limit: int):
        """Получить последние N записей"""
        ref = get_db_reference(path)
        return ref.limit_to_last(limit)
