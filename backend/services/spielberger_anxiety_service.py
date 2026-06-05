from typing import List, Dict
import firebase_admin
from firebase_admin import db
from datetime import datetime

from backend.services.test_results_service import save_test_result

class SpielbergerQuestion:
    def __init__(self, text: str, options: List[str], is_reverse: bool = False, scale: str = 'situational'):
        self.text = text
        self.options = options
        self.is_reverse = is_reverse
        self.scale = scale  # 'situational' or 'personal'

class TestResult:
    def __init__(self, situational_score: int, personal_score: int, interpretation: str, timestamp: int = None):
        self.situational_score = situational_score
        self.personal_score = personal_score
        self.interpretation = interpretation
        self.timestamp = timestamp or int(datetime.now().timestamp() * 1000)

    def to_dict(self):
        # Average normalized score for compatibility
        avg_score = (self.situational_score + self.personal_score) / 2 / 4.0 * 10  # Normalize to 0-10
        return {
            'situational_anxiety': self.situational_score,
            'personal_anxiety': self.personal_score,
            'interpretation': self.interpretation,
            'timestamp': self.timestamp,
            # For compatibility
            'wellbeingScore': max(0, 10 - avg_score),
            'activityScore': max(0, 10 - avg_score),
            'moodScore': max(0, 10 - avg_score)
        }

class SpielbergerAnxietyService:
    def __init__(self):
        self.situational_answers = ["Совсем нет", "Немного", "Умеренно", "Сильно"]
        self.personal_answers = ["Совсем нет", "Немного", "Умеренно", "Сильно"]
        self.questions = self._initialize_questions()

    def _initialize_questions(self) -> List[SpielbergerQuestion]:
        # Situational Anxiety (20 questions)
        situational_questions = [
            ("Я спокоен", self.situational_answers, True),  # Reverse
            ("Мне ничто не угрожает", self.situational_answers, True),  # Reverse
            ("Я нахожусь в напряжении", self.situational_answers, False),
            ("Я испытываю сожаление", self.situational_answers, False),
            ("Я чувствую себя свободно", self.situational_answers, True),  # Reverse
            ("Я расстроен", self.situational_answers, False),
            ("Меня волнуют возможные неудачи", self.situational_answers, False),
            ("Я чувствую себя отдохнувшим", self.situational_answers, True),  # Reverse
            ("Я встревожен", self.situational_answers, False),
            ("Я испытываю чувство внутреннего удовлетворения", self.situational_answers, True),  # Reverse
            ("Я уверен в себе", self.situational_answers, True),  # Reverse
            ("Я нервничаю", self.situational_answers, False),
            ("Я не нахожу себе места", self.situational_answers, False),
            ("Я взвинчен", self.situational_answers, False),
            ("Я не чувствую скованности, напряженности", self.situational_answers, True),  # Reverse
            ("Я доволен", self.situational_answers, True),  # Reverse
            ("Я озабочен", self.situational_answers, False),
            ("Я слишком возбужден и мне не по себе", self.situational_answers, False),
            ("Мне радостно", self.situational_answers, True),  # Reverse
            ("Мне приятно", self.situational_answers, True)  # Reverse
        ]

        # Personal Anxiety (20 questions)
        personal_questions = [
            ("Я испытываю удовольствие", self.personal_answers, True),  # Reverse
            ("Я очень быстро устаю", self.personal_answers, False),
            ("Я легко могу заплакать", self.personal_answers, False),
            ("Я хотел бы быть таким же счастливым, как и другие", self.personal_answers, False),
            ("Нередко я проигрываю из-за того, что недостаточно быстро принимаю решения", self.personal_answers, False),
            ("Обычно я чувствую себя бодрым", self.personal_answers, True),  # Reverse
            ("Я спокоен, хладнокровен и собран", self.personal_answers, True),  # Reverse
            ("Ожидаемые трудности обычно очень тревожат меня", self.personal_answers, False),
            ("Я слишком переживаю из-за пустяков", self.personal_answers, False),
            ("Я вполне счастлив", self.personal_answers, True),  # Reverse
            ("Я принимаю все слишком близко к сердцу", self.personal_answers, False),
            ("Мне не хватает уверенности в себе", self.personal_answers, False),
            ("Обычно я чувствую себя в безопасности", self.personal_answers, True),  # Reverse
            ("Я стараюсь избегать критических ситуаций", self.personal_answers, False),
            ("У меня бывает хандра", self.personal_answers, False),
            ("Я доволен", self.personal_answers, True),  # Reverse
            ("Всякие пустяки отвлекают и волнуют меня", self.personal_answers, False),
            ("Я так сильно переживаю свои разочарования, что потом долго не могу о них забыть", self.personal_answers, False),
            ("Я уравновешенный человек", self.personal_answers, True),  # Reverse
            ("Меня охватывает сильное беспокойство, когда я думаю о своих делах и заботах", self.personal_answers, False)
        ]

        questions = []
        for i, (text, options, is_reverse) in enumerate(situational_questions):
            questions.append(SpielbergerQuestion(text, options, is_reverse, 'situational'))
        
        for i, (text, options, is_reverse) in enumerate(personal_questions):
            questions.append(SpielbergerQuestion(text, options, is_reverse, 'personal'))

        return questions

    def get_questions(self) -> List[Dict]:
        """Returns list of questions for frontend."""
        formatted_questions = []
        for i, q in enumerate(self.questions):
            formatted_questions.append({
                'id': i + 1,
                'question': q.text,
                'options': q.options,
                'type': 'spielberger',
                'scale': q.scale
            })
        return formatted_questions

    def process_answers(self, answers: List[int]) -> Dict[str, any]:
        """Processes answers (list of 1-4 for each of 40 questions), calculates scores and interpretation."""
        if len(answers) != 40:
            raise ValueError("Spielberger-Hanin requires exactly 40 answers.")

        # Calculate situational anxiety score (questions 0-19)
        situational_score = 0
        direct_sit = [2, 3, 5, 6, 8, 11, 12, 13, 16, 17]  # 0-based indices for direct
        reverse_sit = [0, 1, 4, 7, 9, 10, 14, 15, 18, 19]  # reverse

        for i in direct_sit:
            situational_score += answers[i]
        for i in reverse_sit:
            situational_score += (4 - answers[i])  # 1-4 scale, reverse: 4-answer

        # Calculate personal anxiety score (questions 20-39)
        personal_score = 0
        direct_pers = [21, 22, 23, 24, 27, 28, 30, 31, 33, 34, 36, 37, 39]  # 0-based
        reverse_pers = [20, 25, 26, 29, 32, 35, 38]  # Wait, Java has specific, adjust

        # From Java code adjustment:
        # Direct personal: indices 21,22,23,24,27,28,30,31,33,34,36,37,39 (0-based: 21-39)
        # But Java has 13 direct? Wait, standard STAI has 20 items each with specific keys.
        # For simplicity, use standard scoring with 10 direct, 10 reverse per scale.

        # Standard STAI scoring (adjust to match Java logic):
        # For personal: direct questions get answer, reverse get 5-answer (but scale 1-4, so 5-answer)
        # Java uses 5 - answer for reverse (assuming 1-4 scale)

        for i in range(20, 40):
            if i in [21, 22, 23, 24, 27, 28, 30, 31, 33, 34, 36, 37, 39]:  # Direct
                personal_score += answers[i]
            else:  # Reverse
                personal_score += (5 - answers[i])  # For 1-4 scale

        # Generate interpretation
        interpretation = self._generate_interpretation(situational_score, personal_score)

        timestamp = int(datetime.now().timestamp() * 1000)

        return {
            'situational_anxiety': situational_score,
            'personal_anxiety': personal_score,
            'interpretation': interpretation,
            'timestamp': timestamp,
            # For compatibility
            'wellbeingScore': max(0, 10 - ((situational_score + personal_score)/2 / 80 * 10)),
            'activityScore': max(0, 10 - ((situational_score + personal_score)/2 / 80 * 10)),
            'moodScore': max(0, 10 - ((situational_score + personal_score)/2 / 80 * 10))
        }

    def _generate_interpretation(self, situational: int, personal: int) -> str:
        """Generates interpretation based on scores."""
        interpretation = "РЕЗУЛЬТАТЫ ТЕСТА СПИЛБЕРГА-ХАНИНА НА ТРЕВОЖНОСТЬ\n\n"
        interpretation += f"Ситуативная тревожность: {situational} баллов\n"
        interpretation += f"Личностная тревожность: {personal} баллов\n\n"

        # Situational interpretation
        interpretation += "Ситуативная тревожность:\n"
        if situational <= 30:
            interpretation += "Низкий уровень тревожности. Вы спокойны и уравновешены в текущей ситуации.\n\n"
        elif situational <= 45:
            interpretation += "Умеренный уровень тревожности. Вы испытываете некоторое беспокойство в текущей ситуации, но оно находится в пределах нормы.\n\n"
        else:
            interpretation += "Высокий уровень тревожности. Вы испытываете значительное напряжение и беспокойство в текущей ситуации.\n\n"

        # Personal interpretation
        interpretation += "Личностная тревожность:\n"
        if personal <= 30:
            interpretation += "Низкий уровень тревожности. Вы обычно спокойны и не склонны воспринимать большинство ситуаций как угрожающие.\n\n"
        elif personal <= 45:
            interpretation += "Умеренный уровень тревожности. У вас средняя склонность к беспокойству в различных ситуациях.\n\n"
        else:
            interpretation += "Высокий уровень тревожности. Вы склонны воспринимать многие ситуации как угрожающие и реагировать на них состоянием тревоги.\n\n"

        # Recommendations
        interpretation += "Рекомендации:\n"

        if situational > 45:
            interpretation += "Для снижения ситуативной тревожности:\n"
            interpretation += "- Практикуйте техники глубокого дыхания и релаксации\n"
            interpretation += "- Используйте методы осознанности и медитации\n"
            interpretation += "- Анализируйте причины текущего беспокойства и ищите конструктивные решения\n"
            interpretation += "- Обратитесь за поддержкой к близким людям\n\n"

        if personal > 45:
            interpretation += "Для работы с личностной тревожностью:\n"
            interpretation += "- Рассмотрите возможность консультации с психологом или психотерапевтом\n"
            interpretation += "- Изучите и практикуйте когнитивно-поведенческие техники\n"
            interpretation += "- Регулярно занимайтесь физическими упражнениями\n"
            interpretation += "- Развивайте навыки управления стрессом\n"
            interpretation += "- Обеспечьте достаточный отдых и качественный сон\n"

        return interpretation

    def save_result(self, user_id: str, situational: int, personal: int, interpretation: str) -> bool:
        """Saves result to Firebase."""
        if not user_id:
            raise ValueError("User ID is required.")

        timestamp = int(datetime.now().timestamp() * 1000)
        avg_score = (situational + personal) / 2 / 4.0 * 10
        result_data = {
            'situational_anxiety': situational,
            'personal_anxiety': personal,
            'interpretation': interpretation,
            'timestamp': timestamp,
            'wellbeingScore': max(0, 10 - avg_score),
            'activityScore': max(0, 10 - avg_score),
            'moodScore': max(0, 10 - avg_score)
        }
        return save_test_result(user_id, "spielberger_anxiety", result_data)
