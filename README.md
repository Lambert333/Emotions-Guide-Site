# Emotions Guide Site

## Описание

Веб-приложение для отслеживания эмоционального состояния с использованием теста САН (Самочувствие, Активность, Настроение). Пользователи могут регистрироваться, проходить тест, получать персонализированные рекомендации и анализировать прогресс.

## Структура проекта

- **backend/**: FastAPI сервер с Firebase аутентификацией и Realtime Database.
  - **services/**: Логика теста САН в `SAN_test_service.py` и `auth_service.py`.
  - **models.py**: Pydantic модели для API.
  - **main.py**: FastAPI routes.
- **.venv**: Виртуальное окружение Python.
- **requirements.txt**: Зависимости (fastapi, uvicorn, firebase-admin, pydantic).
- **api_specification.json**: OpenAPI спецификация.

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

### Аутентификация

Все защищенные эндпоинты требуют JWT токен в заголовке `Authorization: Bearer <token>`.

- **POST /api/auth/register**  
  Регистрация нового пользователя.  
  **Запрос:**

  ```json
  {
    "email": "user@example.com",
    "password": "password123",
    "username": "Иван Иванов",
    "termsAccepted": true
  }
  ```

  **Ответ (200):**

  ```json
  {
    "userId": "user123",
    "email": "user@example.com",
    "username": "Иван Иванов",
    "accessToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "refreshToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
  }
  ```

  **Ошибки:** 400 (валидация), 409 (пользователь существует).

- **POST /api/auth/login**  
  Вход в систему.  
  **Запрос:**

  ```json
  {
    "email": "user@example.com",
    "password": "password123"
  }
  ```

  **Ответ (200):** Аналогичен register.  
  **Ошибки:** 400 (неверные данные), 401 (аутентификация).

- **POST /api/auth/refresh**  
  Обновление access токена.  
  **Запрос:**

  ```json
  {
    "refreshToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
  }
  ```

  **Ответ (200):** Новые токены.  
  **Ошибки:** 400 (неверный токен), 401.

- **POST /api/auth/logout**  
  Выход с инвалидацией refresh токена.  
  **Запрос:**
  ```json
  {
    "refreshToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
  }
  ```
  **Ответ (200):**
  ```json
  {
    "message": "Успешный выход"
  }
  ```
  **Ошибки:** 400, 401.

### Профиль пользователя

- **GET /api/users/profile**  
  Получение профиля (auth required).  
  **Ответ (200):**

  ```json
  {
    "userId": "user123",
    "email": "user@example.com",
    "username": "Иван Иванов",
    "createdAt": "2024-01-01T00:00:00Z",
    "updatedAt": "2024-01-02T00:00:00Z"
  }
  ```

- **PUT /api/users/profile**  
  Обновление имени.  
  **Запрос:**

  ```json
  {
    "username": "Новое Имя"
  }
  ```

  **Ответ (200):** Обновленный профиль.

- **PUT /api/users/change-email**  
  Смена email (auth required).  
  **Запрос:**

  ```json
  {
    "newEmail": "new@example.com",
    "password": "currentpassword123"
  }
  ```

  **Ответ (200):** Успех.  
  **Ошибки:** 400, 401, 409.

- **PUT /api/users/change-password**  
  Смена пароля.  
  **Запрос:**
  ```json
  {
    "currentPassword": "current123",
    "newPassword": "newpassword123"
  }
  ```
  **Ответ (200):** Успех.

### Тест САН (Самочувствие, Активность, Настроение)

Тест состоит из 30 вопросов (по 10 на категорию). Ответы от 1 до 7. Результаты сохраняются в Firebase Realtime DB.

- **GET /api/san/questions**  
  Получение вопросов (auth required).  
  **Ответ (200):** Массив объектов:

  ```json
  [
    {
      "positive_pole": "Самочувствие хорошее",
      "negative_pole": "Самочувствие плохое",
      "score": 0
    }
    // ... 29 more
  ]
  ```

- **POST /api/san/process**  
  Обработка ответов и генерация интерпретации (auth required, сохраняет результат).  
  **Запрос:**

  ```json
  {
    "answers": [
      4, 5, 3, 6, 2, 7, 1, 4, 5, 3, 6, 2, 7, 1, 4, 5, 3, 6, 2, 7, 1, 4, 5, 3, 6,
      2, 7, 1, 4, 5
    ]
  }
  ```

  **Ответ (200):**

  ```json
  {
    "wellbeing": 4.2,
    "activity": 5.1,
    "mood": 3.8,
    "timestamp": 1726723200000,
    "interpretation": "Хорошее состояние! 🌟\nВы чувствуете себя достаточно хорошо и энергично.\n\nДетали:\n- Показатели находятся на стабильном уровне, есть небольшой потенциал для улучшения.\n\nПриоритетные области для улучшения: настроение 💡\n\nРекомендации: 📋\n- Включи любимую музыку на 10 минут 🎶\n  → Стимулирует выработку дофамина и эндорфинов\n..."
  }
  ```

  **Ошибки:** 400 (неверные ответы), 401.

- **GET /api/test-results**?limit=5  
  Последние результаты (auth required).  
  **Ответ (200):** Массив TestResult.

- **POST /api/test-results**  
  Сохранение прямого результата (альтернатива process).  
  **Запрос:**

  ```json
  {
    "wellbeingScore": 4,
    "activityScore": 5,
    "moodScore": 3,
    "timestamp": "2024-01-02T10:00:00Z"
  }
  ```

- **DELETE /api/test-results**  
  Сброс всех результатов (auth required).

## Тест САН: Логика

- **Категории:** wellbeing (вопросы 1,2,7,8,13,14,19,20,25,26), activity (3,4,9,10,15,16,21,22,27,28), mood (5,6,11,12,17,18,23,24,29,30).
- **Расчет:** Среднее по 10 ответам (1-7).
- **Интерпретация:** Overall score = (wellbeing + activity + mood)/3.
  - > =5.5: Отличное ⭐
  - > =4.5: Хорошее 🌟
  - > =3.5: Нормальное 🌤
  - > =2.5: Пониженное 🌥
  - <2.5: Требуется восстановление ⛅  
    Приоритеты: категории <4.0. Рекомендации на основе комбинаций и низких показателей. Кризис (все <=2): телефон доверия +7 (495) 400-99-99.

## Разработка

- Генерация моделей: fastapi-codegen из api_specification.json.
- Firebase: настройте проект, добавьте creds.json.
- Тестирование: Используйте /docs для Swagger UI.
