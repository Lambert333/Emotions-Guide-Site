from datetime import datetime
from typing import Dict, Any
import requests
from dotenv import load_dotenv
import os
load_dotenv()

from backend.firebase_app import create_firebase_custom_token, get_firebase_auth, get_realtime_db, RealtimeDB
from backend.utils.jwt_utils import decode_refresh_token, generate_refresh_token
import hashlib
import logging

logger = logging.getLogger(__name__)

class AuthService:
    """Сервис аутентификации пользователей с использованием Firebase Authentication"""
    
    def __init__(self):
        self.auth = get_firebase_auth()
        self.db = get_realtime_db()
        self.web_api_key = os.getenv('WEB_API_KEY')
        if not self.web_api_key:
            raise ValueError("WEB_API_KEY not set in .env file. Get it from Firebase Console > Project Settings > General > Web API Key.")
    
    def register(self, email: str, password: str, username: str, terms_accepted: bool) -> Dict[str, Any]:
        """Регистрация нового пользователя"""
        try:
            # Создаем пользователя в Firebase Auth
            user = self.auth.create_user(
                email=email,
                password=password
            )
            uid = user.uid
            
            # Сохраняем дополнительные данные в Realtime DB
            user_data = {
                'email': email,
                'username': username,
                'termsAccepted': terms_accepted,
                'createdAt': datetime.utcnow().isoformat()
            }
            RealtimeDB.set(f'Users/{uid}', user_data)
            
            logger.info(f"Пользователь зарегистрирован в Firebase Auth: {uid}")
            
            # После регистрации, сразу аутентифицируем для получения ID token
            login_result = self.login(email, password)
            if login_result['success']:
                # Обеспечиваем username из register
                login_result['data']['username'] = username
                return login_result
            else:
                # Fallback: Удаляем пользователя если login failed (редко, но для consistency)
                try:
                    self.auth.delete_user(uid)
                    RealtimeDB.delete(f'Users/{uid}')
                except Exception as delete_error:
                    logger.warning(f"Не удалось удалить пользователя при ошибке: {delete_error}")
                return login_result
                
        except Exception as e:
            logger.error(f"Ошибка регистрации: {e}")
            return {
                'success': False,
                'error': str(e)
            }
    
    def login(self, email: str, password: str) -> Dict[str, Any]:
        """Аутентификация с выдачей ID token через REST API"""
        try:
            # Используем Identity Toolkit REST API для signInWithPassword
            url = f"https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key={self.web_api_key}"
            payload = {
                "email": email,
                "password": password,
                "returnSecureToken": True
            }
            response = requests.post(url, json=payload)
            response.raise_for_status()
            data = response.json()
            
            if 'error' in data:
                raise ValueError(data['error']['message'])
            
            uid = data['localId']  # uid из ответа
            id_token = data['idToken']  # ID token для backend-запросов
            firebase_refresh_token = data['refreshToken']  # Firebase refresh token (не используем для blacklist)
            
            # Получаем дополнительные данные из Realtime DB
            user_data = RealtimeDB.get(f'Users/{uid}')
            if not user_data:
                raise ValueError("Профиль пользователя не найден в базе данных")
            
            username = user_data.get('username', 'Пользователь')
            
            # Генерируем custom refresh token для вашего blacklist механизма
            custom_refresh_token = generate_refresh_token(uid)
            
            logger.info(f"Пользователь аутентифицирован: {uid}")
            
            return {
                'success': True,
                'data': {
                    'userId': uid,
                    'email': email,
                    'username': username,
                    'accessToken': id_token,  # Теперь это ID token!
                    'refreshToken': custom_refresh_token  # Ваш custom для logout
                }
            }
        except requests.exceptions.RequestException as e:
            logger.error(f"Ошибка REST API: {e}")
            return {'success': False, 'error': 'Серверная ошибка аутентификации'}
        except ValueError as e:
            logger.error(f"Ошибка логина: {e}")
            return {'success': False, 'error': str(e)}
        except Exception as e:
            logger.error(f"Неожиданная ошибка логина: {e}")
            return {'success': False, 'error': 'Внутренняя ошибка сервера'}

# Глобальный экземпляр сервиса
auth_service = AuthService()

def refresh_tokens(refresh_token: str) -> Dict[str, Any]:
    """Обновление токенов по refresh токену"""
    try:
        # Проверка blacklist
        token_hash = hashlib.sha256(refresh_token.encode()).hexdigest()
        blacklist_entry = RealtimeDB.get(f'InvalidRefreshTokens/{token_hash}')
        if blacklist_entry:
            exp = blacklist_entry.get('exp')
            from datetime import datetime
            if datetime.utcfromtimestamp(exp) > datetime.utcnow():
                raise ValueError('Refresh token invalidated')

        decoded = decode_refresh_token(refresh_token)
        uid = decoded['uid']
        access_token = create_firebase_custom_token(uid)
        new_refresh_token = generate_refresh_token(uid)
        return {
            'success': True,
            'data': {
                'userId': uid,
                'accessToken': access_token,
                'refreshToken': new_refresh_token
            }
        }
    except ValueError as e:
        return {
            'success': False,
            'error': str(e)
        }


def logout_user(refresh_token: str) -> Dict[str, Any]:
    """Инвалидация refresh токена"""
    try:
        decoded = decode_refresh_token(refresh_token)
        uid = decoded['uid']
        token_hash = hashlib.sha256(refresh_token.encode()).hexdigest()
        
        # Проверка, если токен уже инвалидирован
        existing = RealtimeDB.get(f'InvalidRefreshTokens/{token_hash}')
        from datetime import datetime
        if existing:
            existing_exp = existing.get('exp')
            if datetime.utcfromtimestamp(existing_exp) > datetime.utcnow():
                return {
                    'success': False,
                    'error': 'Token already invalidated'
                }
        
        RealtimeDB.set(f'InvalidRefreshTokens/{token_hash}', {
            'uid': uid,
            'exp': decoded['exp']
        })
        return {
            'success': True,
            'message': 'Logout successful'
        }
    except ValueError as e:
        return {
            'success': False,
            'error': str(e)
        }


def register_user(email: str, password: str, username: str, terms_accepted: bool) -> Dict[str, Any]:
    """Удобная функция для регистрации"""
    return auth_service.register(email, password, username, terms_accepted)

def login_user(email: str, password: str) -> Dict[str, Any]:
    """Удобная функция для логина"""
    return auth_service.login(email, password)


def refresh_user_tokens(refresh_token: str) -> Dict[str, Any]:
    """Удобная функция для обновления токенов"""
    return refresh_tokens(refresh_token)


def logout_user_tokens(refresh_token: str) -> Dict[str, Any]:
    """Удобная функция для logout"""
    return logout_user(refresh_token)