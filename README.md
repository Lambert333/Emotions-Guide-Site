# Эмоции Гид

`Эмоции Гид` - full-stack веб-приложение для самонаблюдения за эмоциональным состоянием. В проекте есть авторизация, психологические тесты, сохранение результатов, графики динамики, ИИ-психолог, упражнения для релаксации и профиль пользователя.

Подробное описание текущей функциональности лежит в [FUNCTIONALITY.md](FUNCTIONALITY.md).

## Стек

Frontend:

- React 18, TypeScript, Vite;
- React Router DOM;
- Axios;
- Firebase client SDK;
- Recharts;
- React Toastify;
- React Markdown;
- Lucide React.

Backend:

- FastAPI;
- Pydantic;
- Firebase Admin SDK;
- Firebase Auth;
- Firebase Realtime Database;
- PyJWT;
- SlowAPI;
- HTTPX.

## Структура

```text
Frontend/                 React/Vite приложение
  src/pages/              страницы приложения
  src/components/         общие компоненты
  src/services/api.ts     клиент backend API
  src/firebase/config.ts  Firebase config frontend

backend/                  FastAPI backend
  main.py                 приложение, CORS, endpoint
  models.py               Pydantic-модели
  firebase_app.py         Firebase Admin / Realtime DB
  services/               auth, AI и сервисы тестов
```

## Возможности

- Регистрация и вход пользователя.
- Защищенные страницы через токен авторизации.
- Профиль пользователя, редактирование `username`, смена пароля и выход.
- 8 психологических тестов: САН, эмоциональный интеллект, PSM-25, Спилбергер-Ханин, Бойко, Маслач, самооценка, шкала настроения.
- Сохранение результатов тестов в Firebase Realtime Database.
- Графики динамики по результатам САН.
- ИИ-психолог: чат, анализ эмоционального состояния, история сообщений и cooldown.
- Дыхательное упражнение 4-7-8, таймер медитации и техники релаксации.
- Публичная страница "О нас" с обратной связью и контактами.

## Переменные окружения

Backend использует `backend/.env`. Шаблон:

```bash
cp backend/.env.example backend/.env
```

Основные значения:

- `FIREBASE_SERVICE_ACCOUNT_PATH` - путь к Firebase service account JSON вне репозитория.
- `FIREBASE_DATABASE_URL` - URL Firebase Realtime Database.
- `WEB_API_KEY` - Firebase Web API key для auth-запросов.
- `JWT_SECRET` - секрет refresh-токенов.
- `AI_API_KEY`, `AI_BASE_URL`, `AI_MODEL` - настройки внешнего AI API.
- `CORS_ALLOWED_ORIGINS` - список frontend origins через запятую для CORS.

Если frontend запускается на другом порту или через LAN IP, добавьте точный origin в `CORS_ALLOWED_ORIGINS`, например `http://192.168.1.101:3000`.

Frontend использует `Frontend/.env.local`. Шаблон:

```bash
cp Frontend/.env.example Frontend/.env.local
```

Основная переменная:

```env
VITE_API_BASE_URL=http://localhost:8000
```

## Локальный запуск

Backend:

```bash
python -m venv .venv
. .venv/bin/activate
python -m pip install -r backend/requirements.txt
cp backend/.env.example backend/.env
uvicorn backend.main:app --reload --host 0.0.0.0 --port 8000
```

Frontend:

```bash
cd Frontend
cp .env.example .env.local
npm ci
npm run dev
```

Production build frontend:

```bash
cd Frontend
npm run build
```

После запуска backend OpenAPI доступен по адресу:

```text
http://localhost:8000/docs
```

## Секреты

Не коммитьте реальные секреты и локальные файлы окружения:

- `backend/.env`
- `Frontend/.env`
- `Frontend/.env.local`
- `backend/serviceAccountKey.json`
- `backend/certs.json`

`VITE_*` значения попадают в frontend bundle, поэтому их нельзя считать приватными секретами. Firebase нужно защищать правилами Realtime Database, Auth, ограничениями API key и разрешенными доменами.

## Известные ограничения

- Графики и AI-анализ сейчас работают только с результатами САН.
- Результаты САН и остальных тестов сохраняются в разные ветки Firebase: `Users` и `users`.
- Режим `Все` на графиках использует ограниченный `limit`, а не полную выгрузку истории.
- Расчет тренда на графиках может быть инвертирован из-за порядка сортировки результатов.
- В PSM-25 текущие пороги делают высокий уровень стресса недостижимым при шкале 1-5.
- В шкале настроения есть неточность текста интерпретации относительно фактического диапазона.
- В тесте Бойко есть placeholder-вопросы.

