from typing import List, Dict
import firebase_admin
from firebase_admin import db
from datetime import datetime
import pytz

from backend.services.test_results_service import save_test_result

class SanQuestion:
    def __init__(self, positive_pole: str, negative_pole: str, score: int = 0):
        self.positive_pole = positive_pole
        self.negative_pole = negative_pole
        self.score = score

    def to_dict(self):
        return {
            'positive_pole': self.positive_pole,
            'negative_pole': self.negative_pole,
            'score': self.score
        }

class TestResult:
    def __init__(self, wellbeing: float, activity: float, mood: float, timestamp: int = None):
        self.wellbeing = wellbeing
        self.activity = activity
        self.mood = mood
        self.timestamp = timestamp or int(datetime.now().timestamp() * 1000)

    def to_dict(self):
        return {
            'wellbeing': self.wellbeing,
            'activity': self.activity,
            'mood': self.mood,
            'timestamp': self.timestamp
        }

class SANTestService:
    def __init__(self):
        self.questions = self._initialize_questions()
        self.wellbeing_indices = [0, 1, 6, 7, 12, 13, 18, 19, 24, 25]
        self.activity_indices = [2, 3, 8, 9, 14, 15, 20, 21, 26, 27]
        self.mood_indices = [4, 5, 10, 11, 16, 17, 22, 23, 28, 29]

    def _initialize_questions(self) -> List[SanQuestion]:
        question_list = [
            SanQuestion("Самочувствие плохое", "Самочувствие хорошее"),
            SanQuestion("Чувствую себя слабым", "Чувствую себя сильным"),
            SanQuestion("Пассивный", "Активный"),
            SanQuestion("Малоподвижный", "Подвижный"),
            SanQuestion("Грустный", "Веселый"),
            SanQuestion("Плохое настроение", "Хорошее настроение"),
            SanQuestion("Разбитый", "Работоспособный"),
            SanQuestion("Обессиленный", "Полный сил"),
            SanQuestion("Медлительный", "Быстрый"),
            SanQuestion("Бездеятельный", "Деятельный"),
            SanQuestion("Несчастный", "Счастливый"),
            SanQuestion("Мрачный", "Жизнерадостный"),
            SanQuestion("Напряженный", "Расслабленный"),
            SanQuestion("Больной", "Здоровый"),
            SanQuestion("Безучастный", "Увлеченный"),
            SanQuestion("Равнодушный", "Заинтересованный"),
            SanQuestion("Унылый", "Восторженный"),
            SanQuestion("Печальный", "Радостный"),
            SanQuestion("Усталый", "Отдохнувший"),
            SanQuestion("Изнуренный", "Свежий"),
            SanQuestion("Сонливый", "Возбужденный"),
            SanQuestion("Желание отдохнуть", "Желание работать"),
            SanQuestion("Взволнованный", "Спокойный"),
            SanQuestion("Пессимистичный", "Оптимистичный"),
            SanQuestion("Утомляемый", "Выносливый"),
            SanQuestion("Вялый", "Бодрый"),
            SanQuestion("Соображать трудно", "Соображать легко"),
            SanQuestion("Рассеянный", "Внимательный"),
            SanQuestion("Разочарованный", "Полный надежд"),
            SanQuestion("Недовольный", "Довольный")
        ]
        return question_list

    def get_questions(self) -> List[Dict]:
        """Возвращает список вопросов для фронтенда с options для 7-балльной шкалы."""
        question_list = [
            SanQuestion("Самочувствие плохое", "Самочувствие хорошее"),
            SanQuestion("Чувствую себя слабым", "Чувствую себя сильным"),
            SanQuestion("Пассивный", "Активный"),
            SanQuestion("Малоподвижный", "Подвижный"),
            SanQuestion("Грустный", "Веселый"),
            SanQuestion("Плохое настроение", "Хорошее настроение"),
            SanQuestion("Разбитый", "Работоспособный"),
            SanQuestion("Обессиленный", "Полный сил"),
            SanQuestion("Медлительный", "Быстрый"),
            SanQuestion("Бездеятельный", "Деятельный"),
            SanQuestion("Несчастный", "Счастливый"),
            SanQuestion("Мрачный", "Жизнерадостный"),
            SanQuestion("Напряженный", "Расслабленный"),
            SanQuestion("Больной", "Здоровый"),
            SanQuestion("Безучастный", "Увлеченный"),
            SanQuestion("Равнодушный", "Заинтересованный"),
            SanQuestion("Унылый", "Восторженный"),
            SanQuestion("Печальный", "Радостный"),
            SanQuestion("Усталый", "Отдохнувший"),
            SanQuestion("Изнуренный", "Свежий"),
            SanQuestion("Сонливый", "Возбужденный"),
            SanQuestion("Желание отдохнуть", "Желание работать"),
            SanQuestion("Взволнованный", "Спокойный"),
            SanQuestion("Пессимистичный", "Оптимистичный"),
            SanQuestion("Утомляемый", "Выносливый"),
            SanQuestion("Вялый", "Бодрый"),
            SanQuestion("Соображать трудно", "Соображать легко"),
            SanQuestion("Рассеянный", "Внимательный"),
            SanQuestion("Разочарованный", "Полный надежд"),
            SanQuestion("Недовольный", "Довольный")
        ]
        
        formatted_questions = []
        scale_options = [
            "Полностью согласен с негативным полюсом",
            "Скорее согласен с негативным полюсом",
            "Слегка согласен с негативным полюсом",
            "Нейтрально",
            "Слегка согласен с позитивным полюсом",
            "Скорее согласен с позитивным полюсом",
            "Полностью согласен с позитивным полюсом"
        ]
        for i, q in enumerate(question_list):
            formatted_questions.append({
                'id': i + 1,
                'question': f"{q.positive_pole} - {q.negative_pole}",
                'options': scale_options,  # Добавляем options
                'reversed': False
            })
        return formatted_questions

    def process_answers(self, answers: List[int]) -> Dict[str, any]:
        """Обрабатывает ответы (список из 30 scores от 1 до 7), рассчитывает баллы и интерпретацию."""
        if len(answers) != 30:
            raise ValueError("Должно быть ровно 30 ответов.")
        for a in answers:
            if not 1 <= a <= 7:
                raise ValueError("Ответы должны быть от 1 до 7.")

        # Рассчитываем баллы по категориям (direct scoring: average 1-7, без инверсии)
        wellbeing_score = self._calculate_category_score(answers, self.wellbeing_indices)
        activity_score = self._calculate_category_score(answers, self.activity_indices)
        mood_score = self._calculate_category_score(answers, self.mood_indices)

        # Интерпретация
        interpretation = self._interpret_state(wellbeing_score, activity_score, mood_score)

        timestamp = int(datetime.now().timestamp() * 1000)

        return {
            'wellbeing': round(wellbeing_score, 1),
            'activity': round(activity_score, 1),
            'mood': round(mood_score, 1),
            'timestamp': timestamp,
            'interpretation': interpretation
        }

    def _calculate_category_score(self, answers: List[int], indices: List[int]) -> float:
        """Рассчитывает средний скор для категории (average 1-7, direct scoring)."""
        category_scores = [answers[i] for i in indices]
        return sum(category_scores) / len(indices)

    def _interpret_state(self, wellbeing: float, activity: float, mood: float) -> str:
        """Интерпретирует результаты и генерирует рекомендации как полную строку."""
        state = []
        overall_score = (wellbeing + activity + mood) / 3.0

        # Определяем основной статус
        state.append("")
        if overall_score >= 5.5:
            state.append("Отличное состояние! ⭐")
            state.append("Вы чувствуете себя бодро, активно и в хорошем настроении.")
            state.append("")
            state.append("Детали:")
            state.append("- Ваши показатели сбалансированы, что говорит о гармоничном состоянии.")
        elif overall_score >= 4.5:
            state.append("Хорошее состояние! 🌟")
            state.append("Вы чувствуете себя достаточно хорошо и энергично.")
            state.append("")
            state.append("Детали:")
            state.append("- Показатели находятся на стабильном уровне, есть небольшой потенциал для улучшения.")
        elif overall_score >= 3.5:
            state.append("Нормальное состояние 🌤")
            state.append("Вы чувствуете себя умеренно, с некоторыми колебаниями в самочувствии.")
            state.append("")
            state.append("Детали:")
            state.append("- Показатели в пределах нормы, но есть области, требующие внимания.")
        elif overall_score >= 2.5:
            state.append("Пониженное состояние 🌥")
            state.append("Вы чувствуете некоторую усталость и спад энергии.")
            state.append("")
            state.append("Детали:")
            state.append("- Показатели указывают на необходимость восстановления и отдыха.")
        else:
            state.append("Требуется восстановление ⛅")
            state.append("Вы испытываете значительную усталость и недостаток энергии.")
            state.append("")
            state.append("Детали:")
            state.append("- Показатели говорят о том, что вашему организму нужен отдых и поддержка.")

        # Определяем приоритетные области для улучшения
        priorities = []
        if wellbeing < 4.0:
            priorities.append("самочувствие")
        if activity < 4.0:
            priorities.append("активность")
        if mood < 4.0:
            priorities.append("настроение")

        # Формируем персонализированные рекомендации
        if priorities:
            state.append(f"\nПриоритетные области для улучшения: {', '.join(priorities)} 💡")

        # Добавляем конкретные рекомендации
        state.append("\nРекомендации: 📋")

        # Проверяем критически низкие показатели
        if wellbeing <= 2.0 and activity <= 2.0 and mood <= 2.0:
            state.append("\n❗ Важно:")
            state.append("Если вы находитесь в кризисной ситуации или вам тяжело справиться самостоятельно,")
            state.append("позвоните на Единый телефон доверия: +7 (495) 400-99-99")
            state.append("Квалифицированные специалисты готовы вас выслушать и поддержать 24/7")
            state.append("")

        # Рекомендации на основе комбинаций показателей
        if wellbeing <= 2.0 and activity <= 2.0 and mood <= 2.0:
            state.append("- Отдохни, дружище! 20 минут в тишине с закрытыми глазами 😴")
            state.append("  → Снизит уровень стресса и восстановит энергию")
            state.append("- Попробуй технику 4-7-8: вдох на 4, задержка на 7, выдох на 8 💨")
            state.append("  → Активирует парасимпатическую нервную систему для расслабления")
            state.append("- Прими тёплый душ или ванну 🛀")
            state.append("  → Расслабит мышцы и улучшит кровообращение")
            state.append("- Отложи все дела на 1-2 часа, ты заслужил отдых 😭")
            state.append("  → Даст организму время на восстановление")
            state.append("- Запиши 3 вещи, за которые ты благодарен сегодня 📝")
            state.append("  → Снизит уровень кортизола и повысит уровень серотонина")
        elif wellbeing <= 3.0 and activity >= 5.0:
            state.append("- Не перегружай себя! Добавь 15-минутные перерывы между делами 😴")
            state.append("  → Предотвратит эмоциональное выгорание")
            state.append("- Сделай лёгкую растяжку 5 минут 💃")
            state.append("  → Улучшит кровообращение и снимет мышечное напряжение")
            state.append("- Проверь режим сна: спи не менее 7 часов 😴")
            state.append("  → Обеспечит полноценное восстановление организма")
            state.append("- Попробуй технику прогрессивной мышечной релаксации 💪")
            state.append("  → Снимет физическое и психическое напряжение")
        elif mood <= 3.0 and wellbeing >= 5.0:
            state.append("- Включи любимую музыку на 10 минут 🎶")
            state.append("  → Стимулирует выработку дофамина и эндорфинов")
            state.append("- Позвони близкому человеку 📞")
            state.append("  → Активирует систему социальной поддержки")
            state.append("- Посмотри что-нибудь смешное 😂")
            state.append("  → Вызовет естественный выброс эндорфинов")
            state.append("- Запиши 3 приятных момента за сегодня 📝")
            state.append("  → Перенастроит фокус внимания на позитив")
        elif activity <= 3.0 and mood >= 5.0:
            state.append("- Прогуляйся 15 минут на свежем воздухе 🌍")
            state.append("  → Увеличит уровень кислорода в крови")
            state.append("- Потанцуй под любимую песню 💃")
            state.append("  → Активирует двигательные центры мозга")
            state.append("- Попробуй йогу или лёгкую зарядку 🧘")
            state.append("  → Улучшит кровообращение и повысит энергию")
            state.append("- Сделай 5-минутную технику 4-7-8 💨")
            state.append("  → Оптимизирует работу дыхательной системы")
        elif overall_score >= 5.5:
            state.append("- Поддерживай ритм: 45 минут активности, 10 минут отдыха ⏰")
            state.append("  → Оптимизирует продуктивность и предотвращает усталость")
            state.append("- Попробуй новое хобби или навык 🎯")
            state.append("  → Стимулирует нейропластичность мозга")
            state.append("- Поделись энергией с другими 👋")
            state.append("  → Усилит чувство социальной связанности")
            state.append("- Запланируй активный отдых на выходные 🏞")
            state.append("  → Создаст позитивное ожидание и мотивацию")
            state.append("- Запиши 3 цели на завтра 📝")
            state.append("  → Активирует систему вознаграждения мозга")
        elif overall_score >= 4.5:
            state.append("- Сделай 10-минутную дыхательную гимнастику 💨")
            state.append("  → Нормализует работу вегетативной нервной системы")
            state.append("- Выпей тёплый чай и отдохни 15 минут ☕")
            state.append("  → Снизит уровень стресса и улучшит концентрацию")
            state.append("- Запиши 3 цели на сегодня 📝")
            state.append("  → Создаст структуру и направление действий")
            state.append("- Сделай лёгкую разминку 💪")
            state.append("  → Улучшит кровообращение и повысит бодрость")
            state.append("- Попробуй технику 4-7-8 для расслабления 💨")
            state.append("  → Снизит уровень тревожности")
        elif overall_score >= 3.5:
            state.append("- Позволь себе 5 минут медитации 😴")
            state.append("  → Снизит уровень кортизола и улучшит концентрацию")
            state.append("- Выпей стакан воды 💧")
            state.append("  → Улучшит когнитивные функции и уровень энергии")
            state.append("- Сделай 3-5 простых упражнений 💪")
            state.append("  → Активирует выработку эндорфинов")
            state.append("- Позвони другу 📞")
            state.append("  → Снизит уровень стресса через социальную поддержку")
            state.append("- Запиши 3 вещи, за которые ты благодарен 📝")
            state.append("  → Снизит уровень тревожности и улучшит настроение")
        else:
            state.append("- Сделай паузу: 20 минут отдыха 😴")
            state.append("  → Даст организму время на восстановление")
            state.append("- Выпей тёплый чай ☕")
            state.append("  → Снизит уровень стресса и улучшит концентрацию")
            state.append("- Попробуй технику 4-7-8: вдох на 4, задержка на 7, выдох на 8 💨")
            state.append("  → Активирует парасимпатическую нервную систему")
            state.append("- Послушай спокойную музыку 🎶")
            state.append("  → Снизит уровень кортизола и улучшит настроение")
            state.append("- Запиши 3 приятных момента за сегодня 📝")
            state.append("  → Перенастроит фокус внимания на позитив")

        # Добавляем специфические рекомендации по каждому показателю
        if wellbeing <= 3.0:
            state.append("\nДля улучшения самочувствия: 💪")
            state.append("- Проверь режим сна и питания 😴")
            state.append("  → Обеспечит базовые потребности организма")
            state.append("- Сделай лёгкую растяжку 💃")
            state.append("  → Улучшит кровообращение и гибкость")
            state.append("- Проветри помещение 🌬")
            state.append("  → Увеличит уровень кислорода в крови")
            state.append("- Попробуй технику прогрессивной мышечной релаксации 💪")
            state.append("  → Снимет физическое и психическое напряжение")

        if activity <= 3.0:
            state.append("\nДля повышения активности: 🏃")
            state.append("- Сделай 10 приседаний 💪")
            state.append("  → Активирует крупные мышечные группы")
            state.append("- Пройдись по лестнице 🏃")
            state.append("  → Улучшит кровообращение и повысит энергию")
            state.append("- Сделай 5-минутную зарядку 💪")
            state.append("  → Стимулирует выработку эндорфинов")
            state.append("- Попробуй технику 4-7-8 для бодрости 💨")
            state.append("  → Увеличит уровень кислорода в крови")

        if mood <= 3.0:
            state.append("\nДля улучшения настроения: 😊")
            state.append("- Вспомни приятный момент 😍")
            state.append("  → Активирует позитивные нейронные связи")
            state.append("- Посмотри смешное видео 😂")
            state.append("  → Вызовет естественный выброс эндорфинов")
            state.append("- Позвони другу 📞")
            state.append("  → Активирует систему социальной поддержки")
            state.append("- Запиши 3 вещи, за которые ты благодарен 📝")
            state.append("  → Снизит уровень тревожности и улучшит настроение")

        return "\n".join(state)


    def save_result(self, user_id: str, wellbeing: float, activity: float, mood: float, interpretation: str = "") -> bool:
        """Сохраняет результат в Firebase."""
        if not user_id:
            raise ValueError("Требуется ID пользователя.")

        timestamp = int(datetime.now().timestamp() * 1000)
        result_data = {
            'wellbeingScore': wellbeing,
            'activityScore': activity,
            'moodScore': mood,
            'interpretation': interpretation,
            'timestamp': timestamp
        }
        return save_test_result(user_id, "san", result_data)

    def prepare_san_data_for_ai(self, results: list, username: str, time_data: dict) -> str:
        """
        Форматирует данные САН для ИИ: JSON с тестами (до 25, sorted desc by timestamp),
        динамикой (тренды, сравнение с нормой 4-7), time_of_day/season для каждого, current time_data.
        Если results пусто, возвращает пустой JSON с флагом.
        """
        from backend.utils.time_utils import TimeAndSeasonData
        import json
        from datetime import datetime

        if not results:
            return json.dumps({
                "username": username,
                "tests": [],
                "has_results": False,
                "current": time_data
            })

        # Sorted desc by timestamp
        sorted_results = sorted(results, key=lambda x: x.get('timestamp', 0), reverse=True)[:5]

        tests = []
        for i, res in enumerate(sorted_results):
            ts = res.get('timestamp', 0)
            if ts:
                # Time of day for this test
                test_tz = pytz.timezone('Asia/Yekaterinburg')
                test_dt = datetime.fromtimestamp(ts / 1000, test_tz)
                hour = test_dt.hour
                time_of_day = "утро" if 6 <= hour < 12 else "день" if 12 <= hour < 18 else "вечер" if 18 <= hour < 23 else "ночь"
                month = test_dt.month
                season = "зима" if month in [12, 1, 2] else "весна" if month in [3, 4, 5] else "лето" if month in [6, 7, 8] else "осень"
            else:
                time_of_day = season = "unknown"

            # Trend: comparison with previous test
            trend = {}
            if i > 0:
                prev = tests[-1]
                for key in ['moodScore', 'wellbeingScore', 'activityScore']:
                    if key in res and key in prev:
                        change = res[key] - prev[key]
                        if change > 0:
                            trend[key.replace('Score', '')] = "подросло/улучшилось/повысилось"
                        elif change < 0:
                            trend[key.replace('Score', '')] = "упало/ухудшилось/снизилось"
                        else:
                            trend[key.replace('Score', '')] = "стабильно"

            # Norm status
            wellbeing = res.get('wellbeingScore', 4)
            activity = res.get('activityScore', 4)
            mood = res.get('moodScore', 4)
            norm_status = {
                "wellbeing": "норма" if 4 <= wellbeing <= 7 else "ниже нормы",
                "activity": "норма" if 4 <= activity <= 7 else "ниже нормы",
                "mood": "норма" if 4 <= mood <= 7 else "ниже нормы"
            }

            tests.append({
                "wellbeingScore": wellbeing,
                "activityScore": activity,
                "moodScore": mood,
                "timestamp": ts,
                "timeOfDay": time_of_day,
                "season": season,
                "date": test_dt.strftime("%Y-%m-%d %H:%M") if ts else "unknown",
                "trend": trend,
                "normStatus": norm_status
            })

        data = {
            "username": username,
            "tests": tests,
            "has_results": True,
            "current": time_data,
            "dynamics": f"Динамика: {trend.get('mood', 'стабильно')} настроение с предыдущего теста." if len(tests) > 1 else "Первый тест."
        }

        return json.dumps(data, ensure_ascii=False, separators=(',', ':'))  # Компактный JSON без indent
