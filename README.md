# Emotions Guide Site

## Описание

Веб-приложение для отслеживания эмоционального состояния с использованием теста САН (Самочувствие, Активность, Настроение). Пользователи могут регистрироваться, проходить тест, получать персонализированные рекомендации и анализировать прогресс.

## Структура проекта

- **backend/**: FastAPI сервер с Firebase аутентификацией и Realtime Database.
  - **services/**: Логика теста САН в `SAN_test_service.py` и авторизации в `auth_service.py`.
  - **models.py**: Pydantic модели для API.
  - **main.py**: FastAPI routes.
- **.venv**: Виртуальное окружение Python.
- **requirements.txt**: Зависимости (fastapi, uvicorn, firebase-admin, pydantic).

## Запуск backend

1. Активируйте виртуальное окружение:
   ```
   source .venv/bin/activate  # Linux/Mac
   .venv\Scripts\activate     # Windows
   ```
2. Установите зависимости:
   ```
   pip install -r requirements.txt
   ```
3. Настройте Firebase: добавьте `creds.json` в backend/ (сервисный аккаунт).
4. Запустите сервер:
   ```
   uvicorn backend.main:app --reload --host 0.0.0.0 --port 8000
   ```
5. API docs: http://localhost:8000/docs

## API Спецификация

### Сервис Авторизации

Аутентификация использует Firebase Auth с JWT токенами. Все защищенные эндпоинты требуют заголовок `Authorization: Bearer <access_token>`.

#### 1. Регистрация (/api/auth/register, POST)

- **Описание**: Создать нового пользователя.
- **Тело запроса** (JSON):
  ```
  {
    "email": "user@example.com",
    "password": "password123",
    "username": "Иван Иванов",
    "termsAccepted": true
  }
  ```
- **Ответ (200)**:
  ```
  {
    "userId": "user123",
    "email": "user@example.com",
    "username": "Иван Иванов",
    "accessToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "refreshToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
  }
  ```
- **Ошибки**: 400 (валидация), 409 (пользователь существует).

#### 2. Вход (/api/auth/login, POST)

- **Описание**: Аутентифицировать пользователя.
- **Тело запроса**:
  ```
  {
    "email": "user@example.com",
    "password": "password123"
  }
  ```
- **Ответ (200)**: Аналогично регистрации (токены).
- **Ошибки**: 400 (неверные данные), 401 (ошибка auth).

#### 3. Обновление токена (/api/auth/refresh, POST)

- **Описание**: Получить новый access_token по refresh_token.
- **Тело запроса**:
  ```
  {
    "refreshToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
  }
  ```
- **Ответ (200)**: Новые токены.
- **Ошибки**: 400 (неверный токен), 401 (ошибка).

#### 4. Выход (/api/auth/logout, POST)

- **Описание**: Инвалидировать refresh_token.
- **Тело запроса**:
  ```
  {
    "refreshToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
  }
  ```
- **Ответ (200)**:
  ```
  {
    "message": "Успешный выход"
  }
  ```
- **Ошибки**: 400 (ошибка logout).

#### 5. Профиль (/api/users/profile, GET/PUT)

- **GET**: Получить профиль (auth required).
- **PUT**: Обновить username.
  - Тело: `{"username": "Новое Имя"}`
- **Ответ**: {userId, email, username, createdAt, updatedAt}.

#### 6. Смена email/пароля (/api/users/change-email, /change-password, PUT)

- **change-email**: Тело: {"newEmail": "...", "password": "..."}
- **change-password**: Тело: {"currentPassword": "...", "newPassword": "..." (min 6)}
- **Ответ (200)**: {"message": "Успешно"}

### Тест САН

Тест состоит из 30 вопросов (по 10 на категорию: самочувствие, активность, настроение). Ответы от 1 до 7. Баллы - средние значения.

#### 1. Вопросы (/api/san/questions, GET)

- **Описание**: Получить список вопросов (auth required).
- **Параметры**: limit (1-50, default 30).
- **Ответ (200)**: Массив объектов:
  ```
  [
    {
      "positive_pole": "Самочувствие хорошее",
      "negative_pole": "Самочувствие плохое",
      "score": 0
    },
    ... (30 вопросов)
  ]
  ```

#### 2. Обработка ответов (/api/san/process, POST)

- **Описание**: Рассчитать баллы, интерпретацию и сохранить в DB (auth required).
- **Тело запроса**:
  ```
  {
    "answers": [4, 5, 3, ..., 6]  // 30 значений (1-7)
  }
  ```
- **Ответ (200)**:
  ```
  {
    "wellbeing": 5.2,
    "activity": 4.8,
    "mood": 5.5,
    "timestamp": 1726723200000,
    "interpretation": "Хорошее состояние! 🌟\nВы чувствуете себя достаточно хорошо и энергично.\n\nДетали:\n- Показатели находятся на стабильном уровне, есть небольшой потенциал для улучшения.\n\nПриоритетные области для улучшения: \n\nРекомендации: 📋\n- Сделай 10-минутную дыхательную гимнастику 💨\n  → Нормализует работу вегетативной нервной системы\n..."  // Полный текст
  }
  ```
- **Ошибки**: 400 (неверные ответы, не 30 или вне 1-7).

#### 3. Результаты тестов (/api/test-results)

- **GET**: Последние результаты (auth required).
  - Параметры: limit (1-50, default 5).
  - Ответ: Массив {resultId, userId, activityScore, moodScore, wellbeingScore, timestamp}.
- **POST**: Сохранить готовый результат (альтернатива process).
  - Тело: {"activityScore": 5, "moodScore": 6, "wellbeingScore": 4, "timestamp": "..."}
- **DELETE**: Сброс всех результатов (auth required).
- **Ответы**: SuccessResponse или список TestResult.

## Тест САН: Детали интерпретации

- **Расчет**: Средние баллы по категориям (1-7).
- **Overall score**: (wellbeing + activity + mood) / 3.
- **Статусы**:
  - ≥5.5: Отличное состояние! ⭐
  - ≥4.5: Хорошее состояние! 🌟
  - ≥3.5: Нормальное состояние 🌤
  - ≥2.5: Пониженное состояние 🌥
  - <2.5: Требуется восстановление ⛅
- **Приоритеты**: Категории <4.0 (самочувствие, активность, настроение).
- **Рекомендации**: Персонализированные на основе комбинаций (кризис, дисбаланс) + специфические по показателям.
- **Кризис**: Если все ≤2.0, добавить телефон доверия +7 (495) 400-99-99.

## Разработка

- Для генерации моделей: fastapi-codegen из api_specification.json.
- Firebase: настройте проект, добавьте creds.json.
- Тестирование: Используйте /docs для Swagger UI.
