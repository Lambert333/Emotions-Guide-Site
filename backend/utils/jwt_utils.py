import os
from datetime import datetime, timedelta
import jwt

def generate_refresh_token(uid: str, secret: str = None) -> str:
    """Генерация refresh токена"""
    if secret is None:
        secret = os.getenv('JWT_SECRET')
        if not secret:
            raise ValueError("JWT_SECRET не установлен в .env")
    
    payload = {
        'uid': uid,
        'iat': datetime.utcnow(),
        'exp': datetime.utcnow() + timedelta(days=30)
    }
    return jwt.encode(payload, secret, algorithm='HS256')

def decode_refresh_token(token: str, secret: str = None) -> dict:
    """Декодирование refresh токена"""
    if secret is None:
        secret = os.getenv('JWT_SECRET')
        if not secret:
            raise ValueError("JWT_SECRET не установлен в .env")
    
    try:
        return jwt.decode(token, secret, algorithms=['HS256'])
    except jwt.ExpiredSignatureError:
        raise ValueError("Refresh token истек")
    except jwt.InvalidTokenError:
        raise ValueError("Неверный refresh token")