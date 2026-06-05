from typing import List, Dict
import firebase_admin
from firebase_admin import db
from datetime import datetime

from backend.services.test_results_service import save_test_result

class MoodQuestion:
    def __init__(self, text: str, affect_type: str):
        self.text = text
        self.affect_type = affect_type  # 'positive' or 'negative'

class TestResult:
    def __init__(self, positive_affect: int, negative_affect: int, mood_balance: int, interpretation: str, timestamp: int = None):
        self.positive_affect = positive_affect
        self.negative_affect = negative_affect
        self.mood_balance = mood_balance
        self.interpretation = interpretation
        self.timestamp = timestamp or int(datetime.now().timestamp() * 1000)

    def to_dict(self):
        # Normalize mood balance to 0-10
        normalized_mood = (self.mood_balance + 20) / 40.0 * 10  # From -20 to 20 -> 0-10
        return {
            'positive_affect': self.positive_affect,
            'negative_affect': self.negative_affect,
            'mood_balance': self.mood_balance,
            'interpretation': self.interpretation,
            'timestamp': self.timestamp,
            # For compatibility
            'wellbeingScore': max(0, min(10, normalized_mood)),
            'activityScore': max(0, min(10, normalized_mood)),
            'moodScore': max(0, min(10, normalized_mood))
        }

class MoodScaleService:
    def __init__(self):
        self.questions = self._initialize_questions()
        self.standard_answers = ["Никогда", "Редко", "Иногда", "Часто", "Всегда"]  # 1-5 scale

    def _initialize_questions(self) -> List[MoodQuestion]:
        # 10 questions: 5 positive affect, 5 negative affect (alternating)
        questions_data = [
            ("Я чувствую себя радостным", 'positive'),
            ("Я испытываю грусть", 'negative'),
            ("Я полон энергии", 'positive'),
            ("Я чувствую тревогу", 'negative'),
            ("Я чувствую себя воодушевленным", 'positive'),
            ("Я чувствую раздражение", 'negative'),
            ("Я испытываю интерес к происходящему", 'positive'),
            ("Я чувствую усталость", 'negative'),
            ("Я чувствую удовлетворение", 'positive'),
            ("Я чувствую беспокойство", 'negative')
        ]
        
        return [MoodQuestion(text, affect_type) for text, affect_type in questions_data]

    def get_questions(self) -> List[Dict]:
        """Returns list of questions for frontend."""
        formatted_questions = []
        for i, q in enumerate(self.questions):
            formatted_questions.append({
                'id': i + 1,
                'question': q.text,
                'options': self.standard_answers,
                'type': 'mood_scale',
                'affect_type': q.affect_type
            })
        return formatted_questions

    def process_answers(self, answers: List[int]) -> Dict[str, any]:
        """Processes answers (list of 1-5 for each of 10 questions), calculates positive/negative affect and balance."""
        if len(answers) != 10:
            raise ValueError("Mood Scale requires exactly 10 answers.")

        # Positive affect: questions 0,2,4,6,8 (1-based: 1,3,5,7,9)
        positive_affect = sum(answers[i] for i in [0, 2, 4, 6, 8])
        
        # Negative affect: questions 1,3,5,7,9 (1-based: 2,4,6,8,10)
        negative_affect = sum(answers[i] for i in [1, 3, 5, 7, 9])
        
        # Mood balance: positive - negative (range -20 to 20)
        mood_balance = positive_affect - negative_affect

        # Generate interpretation
        interpretation = self._generate_interpretation(positive_affect, negative_affect, mood_balance)

        timestamp = int(datetime.now().timestamp() * 1000)

        return {
            'positive_affect': positive_affect,
            'negative_affect': negative_affect,
            'mood_balance': mood_balance,
            'interpretation': interpretation,
            'timestamp': timestamp,
            # For compatibility 0-10
            'wellbeingScore': max(0, min(10, (mood_balance + 20) / 40.0 * 10)),
            'activityScore': max(0, min(10, (mood_balance + 20) / 40.0 * 10)),
            'moodScore': max(0, min(10, (mood_balance + 20) / 40.0 * 10))
        }

    def _generate_interpretation(self, positive: int, negative: int, balance: int) -> str:
        """Generates interpretation based on mood scores."""
        interpretation = "РЕЗУЛЬТАТЫ ШКАЛЫ ОЦЕНКИ НАСТРОЕНИЯ\n\n"
        interpretation += f"Позитивный аффект: {positive} из 20\n"
        interpretation += f"Негативный аффект: {negative} из 20\n"
        interpretation += f"Баланс настроения: {balance}\n\n"

        # Overall mood balance interpretation
        if balance > 10:
            interpretation += "У вас очень позитивное настроение. Вы испытываете много положительных эмоций и мало отрицательных.\n\n"
            interpretation += "Характеристики вашего текущего эмоционального состояния:\n"
            interpretation += "• Высокий уровень энергии и энтузиазма\n"
            interpretation += "• Оптимистичный взгляд на жизнь\n"
            interpretation += "• Ощущение радости и удовлетворения\n"
            interpretation += "• Низкий уровень тревоги и беспокойства\n"
            interpretation += "• Высокая мотивация и готовность к действиям\n\n"
            
            interpretation += "Рекомендации:\n"
            interpretation += "• Используйте это позитивное состояние для решения сложных задач\n"
            interpretation += "• Делитесь своим позитивным настроением с окружающими\n"
            interpretation += "• Отмечайте, какие факторы способствуют вашему хорошему настроению\n"
            interpretation += "• Практикуйте благодарность для поддержания позитивного настроя\n"
        elif balance > 0:
            interpretation += "У вас умеренно позитивное настроение. Положительные эмоции преобладают над отрицательными.\n\n"
            interpretation += "Характеристики вашего текущего эмоционального состояния:\n"
            interpretation += "• Достаточный уровень энергии\n"
            interpretation += "• В целом позитивный взгляд на ситуации\n"
            interpretation += "• Преобладание приятных эмоций\n"
            interpretation += "• Умеренный уровень мотивации\n"
            interpretation += "• Присутствие некоторых негативных эмоций\n\n"
            
            interpretation += "Рекомендации:\n"
            interpretation += "• Обратите внимание на факторы, которые вызывают негативные эмоции\n"
            interpretation += "• Практикуйте техники релаксации для снижения стресса\n"
            interpretation += "• Уделяйте время приятным занятиям для поддержания позитивного настроя\n"
            interpretation += "• Развивайте навыки управления эмоциями\n"
        elif balance > -10:
            interpretation += "У вас умеренно негативное настроение. Отрицательные эмоции преобладают над положительными.\n\n"
            interpretation += "Характеристики вашего текущего эмоционального состояния:\n"
            interpretation += "• Сниженный уровень энергии\n"
            interpretation += "• Тенденция к негативной оценке ситуаций\n"
            interpretation += "• Преобладание неприятных эмоций\n"
            interpretation += "• Возможное наличие тревоги или раздражительности\n"
            interpretation += "• Снижение мотивации\n\n"
            
            interpretation += "Рекомендации:\n"
            interpretation += "• Практикуйте техники управления стрессом (глубокое дыхание, медитация)\n"
            interpretation += "• Обратите внимание на негативные мысли и попробуйте их переформулировать\n"
            interpretation += "• Уделите время физической активности\n"
            interpretation += "• Общайтесь с поддерживающими людьми\n"
            interpretation += "• Обеспечьте себе достаточный отдых\n"
            interpretation += "• Если негативное настроение сохраняется длительное время, рассмотрите возможность консультации специалиста\n"
        else:
            interpretation += "У вас выраженное негативное настроение. Отрицательные эмоции значительно преобладают над положительными.\n\n"
            interpretation += "Характеристики вашего текущего эмоционального состояния:\n"
            interpretation += "• Низкий уровень энергии\n"
            interpretation += "• Пессимистичный взгляд на ситуации\n"
            interpretation += "• Выраженные негативные эмоции (грусть, тревога, раздражение)\n"
            interpretation += "• Трудности с концентрацией и принятием решений\n"
            interpretation += "• Значительное снижение мотивации\n\n"
            
            interpretation += "Рекомендации:\n"
            interpretation += "• Обратитесь к психологу или психотерапевту для профессиональной поддержки\n"
            interpretation += "• Практикуйте техники самопомощи при стрессе и тревоге\n"
            interpretation += "• Обеспечьте себе достаточный отдых и сон\n"
            interpretation += "• Поддерживайте регулярную физическую активность\n"
            interpretation += "• Ограничьте потребление новостей и социальных сетей\n"
            interpretation += "• Обратитесь за поддержкой к близким людям\n"
            interpretation += "• Уделите внимание базовым потребностям (питание, сон, отдых)\n"

        # Positive affect analysis
        interpretation += "\nАНАЛИЗ ПОЗИТИВНОГО АФФЕКТА:\n"
        if positive < 8:
            interpretation += "Низкий уровень позитивного аффекта может указывать на сниженное настроение, апатию или депрессивные тенденции. Рекомендуется обратить внимание на источники радости и удовольствия в вашей жизни.\n"
        elif positive < 14:
            interpretation += "Средний уровень позитивного аффекта говорит о наличии положительных эмоций, но есть потенциал для их усиления. Обратите внимание на занятия, которые приносят вам радость и удовлетворение.\n"
        else:
            interpretation += "Высокий уровень позитивного аффекта свидетельствует о хорошем эмоциональном состоянии, энтузиазме и энергичности. Продолжайте заниматься тем, что приносит вам положительные эмоции.\n"

        # Negative affect analysis
        interpretation += "\nАНАЛИЗ НЕГАТИВНОГО АФФЕКТА:\n"
        if negative < 8:
            interpretation += "Низкий уровень негативного аффекта указывает на отсутствие выраженных отрицательных эмоций, что является хорошим показателем эмоционального благополучия.\n"
        elif negative < 14:
            interpretation += "Средний уровень негативного аффекта говорит о наличии некоторых отрицательных эмоций. Обратите внимание на их источники и практикуйте техники управления стрессом.\n"
        else:
            interpretation += "Высокий уровень негативного аффекта свидетельствует о значительном эмоциональном дискомфорте. Рекомендуется обратить внимание на источники стресса и тревоги, а также рассмотреть возможность консультации специалиста.\n"

        return interpretation

    def save_result(self, user_id: str, positive: int, negative: int, balance: int, interpretation: str) -> bool:
        """Saves result to Firebase."""
        if not user_id:
            raise ValueError("User ID is required.")

        timestamp = int(datetime.now().timestamp() * 1000)
        normalized_mood = (balance + 20) / 40.0 * 10
        result_data = {
            'positive_affect': positive,
            'negative_affect': negative,
            'mood_balance': balance,
            'interpretation': interpretation,
            'timestamp': timestamp,
            'wellbeingScore': max(0, min(10, normalized_mood)),
            'activityScore': max(0, min(10, normalized_mood)),
            'moodScore': max(0, min(10, normalized_mood))
        }
        return save_test_result(user_id, "mood_scale", result_data)
