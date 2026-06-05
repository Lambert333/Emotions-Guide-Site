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
Объясни пользователю {username} в тёплом, поддерживающем стиле (300–400 слов), почему регулярное прохождение психологических тестов приложения важно:
1) Отслеживание эмоционального состояния, стресса, тревожности, самооценки и выгорания.
2) Повышение самосознания и понимания своих эмоций.
3) Получение персонализированных рекомендаций для заботы о себе.
Используй markdown для форматирования: **жирный** для выделения, *курсив* для акцента. Избегай лишних пустых строк между абзацами.
Учти время года ({season}) и время суток ({time_of_day}) для примеров.
Используй тёплый, нейтральный тон, как у заботливого друга. Избегай названий городов, часовых поясов, медицинских диагнозов и сложных терминов.
Добавляй не более 4–5 эмодзи для мягкости. Ссылайся на историю результатов и графики в приложении.
Завершай вдохновляющей фразой."""
        self.results_not_empty_prompt = """Ты — trauma-informed ИИ-ассистент в приложении для ментального благополучия, созданного для русскоязычной аудитории 18–35 лет.
        Анализируй результаты психологических тестов пользователя {username} и предоставь эмпатичный, поддерживающий анализ (300–400 слов).
        Все рекомендации ИСКЛЮЧИТЕЛЬНО рекомендательные, медицинские диагнозы строго запрещены.
        Учитывай время года ({season}) и время суток ({time_of_day}) для релевантных рекомендаций.
        В данных могут быть разные testType: san, emotional_intelligence, psm25_stress, spielberger_anxiety, boyko_burnout, maslach_burnout, self_esteem, mood_scale.
        Для testType="san" используй шкалу 1–7: 1–3 низко, 4 нейтрально, 5–7 хорошо. Для остальных тестов опирайся на scores и interpretation, не смешивай разные методики в одну шкалу.
        Сформируй один общий вывод по истории результатов: что сейчас заметно, какие сигналы повторяются, что можно мягко попробовать дальше.
        Если есть результаты САН, можно ссылаться на графики самочувствия, активности и настроения. Если есть другие тесты, упоминай их человекочитаемыми названиями.
        Структура ответа:
        А) короткий анализ текущего состояния и динамики;
        Б) 2–3 бережные рекомендации, привязанные к данным, времени года и суток;
        В) поддерживающая завершающая фраза.
        Используй markdown, не более 4–5 эмодзи, не показывай JSON пользователю, не ставь диагнозы.
        Данные: {json_data}
        ГЕНЕРИРУЙ ТОЛЬКО ОДИН coherent анализ всей динамики (300–400 слов). НЕ генерируй отдельные блоки для каждого теста и НЕ повторяй приветствия."""

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
