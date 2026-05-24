import os
import re
import asyncio
import time
import logging
from typing import List, Dict, AsyncGenerator, Optional
import httpx
from dotenv import load_dotenv

load_dotenv(dotenv_path=os.path.join(os.path.dirname(__file__), '..', '.env'))

logger = logging.getLogger(__name__)

class AIService:
    """
    Сервис для интеграции с ИИ API (intelligence.io.solutions, модель openai/gpt-oss-120b).
    Поддержка стриминга SSE, фильтрации ответов, retry.
    """
    def __init__(self):
        self.api_key = self._normalize_api_key(os.getenv('AI_API_KEY', ''))
        if not self.api_key:
            raise ValueError("AI_API_KEY not set in .env. Use OpenAI API key (sk-...)")
        self.base_url = os.getenv("AI_BASE_URL", "https://api.intelligence.io.solutions/api/v1").rstrip("/")
        self.model = os.getenv("AI_MODEL", "openai/gpt-oss-120b")
        self.auth_header = os.getenv("AI_AUTH_HEADER", self._default_auth_header(self.api_key)).lower()
        self.timeout = httpx.Timeout(
            connect=float(os.getenv("AI_CONNECT_TIMEOUT", "5")),
            read=float(os.getenv("AI_READ_TIMEOUT", "45")),
            write=float(os.getenv("AI_WRITE_TIMEOUT", "10")),
            pool=float(os.getenv("AI_POOL_TIMEOUT", "5")),
        )
        self.headers = self._build_headers()
        self.max_retries = 0  # Временно отключить retry для избежания множественных вызовов
        self.system_prompt_chat = """
        Ты - эмпатичный и профессиональный психолог-консультант. Отвечай на русском языке, кратко, но информативно.
        Будь поддерживающим, без постановки диагнозов. Рекомендации носят рекомендательный характер.
        Используй эмодзи умеренно (≤5). Структура: эмпатия + анализ + 1-2 рекомендации.
        Используй markdown для форматирования: **жирный** для выделения, *курсив* для акцента. Для рекомендаций используй маркированный список с - или нумерованный с 1., 2. Избегай лишних пустых строк между абзацами — используй одну пустую строку только между основными разделами (эмпатия, анализ, рекомендации).
        Если нужно размышлять, используй <think>...</think>, но не показывай пользователю.
                """
        self.results_empty_prompt = """Ты — эмпатичный ИИ-психолог в приложении для ментального благополучия, созданного для русскоязычной аудитории 18–35 лет.
Объясни пользователю {username} в тёплом, поддерживающем стиле (300–400 слов), почему регулярное прохождение тестов САН (самочувствие, активность, настроение) важно:
1) Отслеживание эмоционального состояния (например, как стресс влияет на настроение).
2) Повышение самосознания (понимание своих эмоций).
3) Получение персонализированных рекомендаций для заботы о себе.
Используй markdown для форматирования: **жирный** для выделения, *курсив* для акцента. Избегай лишних пустых строк между абзацами — используй одну пустую строку только между основными разделами.
Учти время года ({season}) и время суток ({time_of_day}) для примеров (например, прогулка летом, тёплый чай зимним вечером).
Используй тёплый, нейтральный тон, как у заботливого друга. Избегай названий городов и упоминаний часового пояса, ссылайся только на время года и суток.
Добавляй не более 4–5 эмодзи (😊, 🌟, 🛌, ☀️, 🌙) для мягкости и выразительности. Ссылайся на графики в приложении.
Завершай вдохновляющей фразой (например, 'Каждый шаг к себе — это прогресс! 🌟').
Избегай медицинских терминов и диагнозов."""
        self.results_not_empty_prompt = """Ты — trauma-informed ИИ-ассистент в приложении для ментального благополучия, созданного для русскоязычной аудитории 18–35 лет.
        Анализируй результаты теста САН (самочувствие, активность, настроение) для пользователя {username} и предоставь эмпатичный, поддерживающий анализ (300–400 слов).
        Все рекомендации ИСКЛЮЧИТЕЛЬНО рекомендательные, медицинские диагнозы строго запрещены. Пользователь не может вести диалог, только запросить повторный анализ.
        Учитывай время года ({season}: дек–фев — зима, мар–май — весна, июн–авг — лето, сен–ноя — осень) и время суток ({time_of_day}: утро 06:00–12:00, день 12:00–18:00, вечер 18:00–23:00, ночь 23:00–06:00) для релевантных рекомендаций.
        Избегай упоминаний часового пояса или названий городов, ссылайся только на время года и суток. Ссылайся на графики самочувствия, активности и настроения в приложении.
        Для разнообразия варьируй формулировки и приветствия. Следуй этим шагам:
        1. **Анализ данных теста САН**:
           - Оцени до 25 последних результатов теста САН (или все доступные, если их меньше). Шкала: 1–7 (1–3 — низкие, возможный дискомфорт; 4 — нейтральные; 5–7 — высокие, норма).
           - Сравни текущие показатели с нормой (4–7).
           - Опиши динамику изменений на графиках приложения (улучшение 😊, ухудшение 😔, стабильность ➡️), если есть предыдущие тесты, с вариативными формулировками (например, 'настроение немного подросло' или 'самочувствие стало ниже').
           - Если есть поле 'note', кратко упомяни его в анализе.
        2. **Trauma-informed интерпретация**:
           - Опиши эмоциональное состояние в тёплом, поддерживающем стиле, как у заботливого друга (например, 'похоже, день был непростым' или 'ты в хорошем ресурсе'). Низкие значения (≤3) рассматривай как сигнал возможного эмоционального дискомфорта, но избегай медицинских терминов.
           - Учти возможный стресс от учёбы, работы или социальной жизни, но не предполагай причин без данных.
        3. **Рекомендации**:
           - Выбери 2–3 практики из пула, адаптированные к состоянию, времени года и суток. Вариируй формулировки для естественности. Пул практик:
             - **Низкие показатели (≤3)**:
               - Ночь: лечь спать (🛌), расслабляющая музыка, дыхательные упражнения (4-4-6 или квадратное дыхание).
               - Утро: лёгкая зарядка (☀️), дыхательное упражнение для бодрости, постановка небольшой цели.
               - День: техника grounding (5-4-3-2-1), прогулка, замена негативной мысли (например, 'я не справлюсь' на 'я делаю, что могу').
               - Вечер: письмо себе, лёгкая растяжка, тёплый чай (🌙).
               - Зима/вечер/ночь: тёплая ванна, горячий чай.
               - Лето/утро/день: прогулка, лёгкая физическая активность.
             - **Нейтральные/высокие (≥4)**:
               - Ночь: чтение книги (🛌), короткая медитация перед сном, расслабляющая музыка.
               - Утро: дневник благодарности (☀️), постановка цели на день, прослушивание любимой музыки.
               - День: творческое занятие (рисование, заметки), прогулка, беседа с другом.
               - Вечер: просмотр вдохновляющего видео, дневник благодарности, лёгкая растяжка (🌙).
             - **Общие, с учётом времени года/суток**: прогулка (летом/утром/днем), танцы под музыку, постановка небольшой цели (например, 'выучить 5 новых слов'), чтение книги (зимой/вечером/ночь), беседа с другом, создание коллажа идей (весной/днем).
           - Для ночного времени (23:00–06:00) с низкими показателями (≤3) приоритетно предлагай лечь спать, предполагая, что пользователь не работает ночью.
           - Привяжи рекомендации к показателям, времени года и суток (например, 'летней ночью попробуй лечь спать пораньше 🛌' или 'утром попробуй лёгкую зарядку ☀️').
        4. **Формат ответа**:
           - Используй тёплый, нейтральный тон, как у заботливого друга, с вариативными приветствиями (например, 'Здравствуйте, {username}, давайте посмотрим на ваши результаты? 😊' или 'Привет, {username}, как дела сегодня? 🌟').
           - Структура:
             А) Анализ текущих результатов и динамики на графиках с эмодзи (😊, 😔, ➡️, не более 4–5 в тексте).\n
             Б) 2–3 рекомендации, привязанные к показателям, времени года и суток, в виде маркированного списка.\n
             В) Вдохновляющая фраза (например, 'Ты делаешь важный шаг для себя! 🌟' или 'Каждый день — новая возможность! ☀️').\n
           - Используй markdown для форматирования: **жирный** для выделения, *курсив* для акцента. Для рекомендаций используй маркированный список с - или нумерованный с 1., 2. Избегай лишних пустых строк между абзацами — используй одну пустую строку только между основными разделами (анализ, рекомендации, заключение).
           - Используй не более 4–5 эмодзи (😊, 😔, ➡️, 🌟, 🛌, ☀️, 🌙) для мягкости и выразительности. Избегай медицинских терминов, диагнозов и сложного языка. Подчеркивай эмоциональную безопасность.
        Данные: {json_data}
        ГЕНЕРИРУЙ ТОЛЬКО ОДИН coherent анализ всей динамики (300–400 слов). НЕ генерируй отдельные блоки для каждого теста, НЕ повторяй приветствия или структуру. Оцени общую тенденцию изменений на графиках, сравни с нормой (4-7), опиши динамику (улучшение/ухудшение/стабильность), учти note если есть, адаптируй рекомендации к текущему времени года/суток.
        Пример ввода: Самочувствие: 3, Активность: 4, Настроение: 2, Note: 'только текущий тест', Время: {time_of_day}, сезон: {season}."""

    def _normalize_api_key(self, api_key: str) -> str:
        """Accept a raw key or a copied 'Bearer ...' value from .env."""
        api_key = api_key.strip()
        if api_key.lower().startswith("bearer "):
            return api_key[7:].strip()
        return api_key

    def _default_auth_header(self, api_key: str) -> str:
        """
        io.net sub-keys are documented as authenticating inference calls via
        x-api-key. Regular IO Intelligence API keys use Authorization: Bearer.
        """
        if api_key.startswith("io-v2-") or "-v2-" in api_key:
            return "x-api-key"
        return "authorization"

    def _build_headers(self) -> Dict[str, str]:
        headers = {"Content-Type": "application/json"}
        if self.auth_header == "x-api-key":
            headers["x-api-key"] = self.api_key
        elif self.auth_header == "authorization":
            headers["Authorization"] = f"Bearer {self.api_key}"
        else:
            raise ValueError("AI_AUTH_HEADER must be either 'authorization' or 'x-api-key'")
        return headers

    async def send_request(
        self, 
        system_prompt: str, 
        user_message: str, 
        history: List[Dict[str, str]] = None, 
        stream: bool = True,
        max_tokens: int = 1000
    ) -> AsyncGenerator[str, None]:
        """
        Отправляет запрос к ИИ. Если stream=True, yield чанки; иначе возвращает полный текст.
        history: List[{"role": "user/assistant", "content": "..."}]
        """
        if history is None:
            history = []

        messages = [{"role": "system", "content": system_prompt}]
        messages.extend(history)
        if user_message:
            messages.append({"role": "user", "content": user_message})

        payload = {
            "model": self.model,
            "messages": messages,
            "max_tokens": max_tokens,
            "stream": stream,
            "temperature": 0.7
        }

        async with httpx.AsyncClient() as client:
            response = None
            for attempt in range(self.max_retries + 1):
                try:
                    response = await client.post(
                        f"{self.base_url}/chat/completions",
                        json=payload,
                        headers=self.headers,
                        timeout=self.timeout
                    )
                    response.raise_for_status()
                    logger.info("AI provider response status: %s", response.status_code)

                    if stream:
                        full_response = ""
                        async for line in response.aiter_lines():
                            if line.startswith("data: "):
                                data = line[6:].strip()
                                if data == "[DONE]":
                                    break
                                try:
                                    import json
                                    chunk = json.loads(data)
                                    if "choices" in chunk and chunk["choices"]:
                                        delta = chunk["choices"][0].get("delta", {}).get("content", "")
                                        if delta:
                                            filtered_delta = self._filter_response(delta)
                                            full_response += filtered_delta
                                            yield filtered_delta
                                    else:
                                        continue  # Skip invalid or empty chunks
                                except json.JSONDecodeError:
                                    continue
                        logger.info("AI streamed response length: %s", len(full_response))
                        if not full_response:
                            yield "Извините, не удалось получить ответ. Попробуйте еще раз."
                    else:
                        result = response.json()
                        content = result.get("choices", [{}])[0].get("message", {}).get("content", "")
                        yield self._filter_response(content)

                except httpx.TimeoutException:
                    if attempt < self.max_retries:
                        await asyncio.sleep(2 ** attempt)  # Exponential backoff
                        continue
                    raise ValueError(
                        f"AI provider timeout: {self.base_url}, model={self.model}"
                    )
                except httpx.HTTPStatusError as e:
                    status_code = e.response.status_code
                    response_text = e.response.text[:500]
                    logger.error(
                        "AI provider HTTP error: status=%s model=%s body=%s",
                        status_code,
                        self.model,
                        response_text,
                    )
                    raise ValueError(
                        f"AI provider HTTP error {status_code}: {response_text}"
                    )
                except httpx.RequestError as e:
                    if attempt < self.max_retries and (response is None or (response and response.status_code == 504)):
                        await asyncio.sleep(2 ** attempt + 1)  # Backoff 1-3s for 504
                        continue
                    logger.error("AI provider request error: model=%s error=%s", self.model, e)
                    raise ValueError(f"AI provider request error: {e}")

    def _filter_response(self, text: str) -> str:
        """Удаляет <think>...</think> из текста."""
        return re.sub(r"<think>.*?</think>", "", text, flags=re.DOTALL).strip()

# Пример (async):
# async def example():
#     ai = AIService()
#     async for chunk in ai.send_request(ai.system_prompt_chat, "Привет, как дела?"):
#         print(chunk, end="")
