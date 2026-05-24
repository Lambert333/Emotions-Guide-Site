from typing import List, Dict
import firebase_admin
from firebase_admin import db
from datetime import datetime
import pytz

class EmotionalIntelligenceQuestion:
    def __init__(self, text: str, options: List[str]):
        self.text = text
        self.options = options

class TestResult:
    def __init__(self, ei_score: float, interpretation: str, timestamp: int = None):
        self.ei_score = ei_score
        self.interpretation = interpretation
        self.timestamp = timestamp or int(datetime.now().timestamp() * 1000)

    def to_dict(self):
        return {
            'ei_score': self.ei_score,
            'interpretation': self.interpretation,
            'timestamp': self.timestamp,
            # For compatibility with existing schema
            'wellbeingScore': self.ei_score,
            'activityScore': self.ei_score,
            'moodScore': self.ei_score
        }

class EmotionalIntelligenceService:
    def __init__(self):
        self.standard_answers = ["Никогда", "Редко", "Иногда", "Часто", "Всегда"]
        self.questions = self._initialize_questions()

    def _initialize_questions(self) -> List[EmotionalIntelligenceQuestion]:
        # Questions based on the Java implementation (expanded with standard EI questions)
        question_texts = [
            "Я хорошо понимаю свои эмоции",
            "Я могу точно определить, что чувствуют другие люди",
            "Я легко распознаю свои эмоциональные состояния",
            "Я умею контролировать свои эмоции в стрессовых ситуациях",
            "Я эмпатичен к чувствам других",
            "Я могу мотивировать себя в трудные моменты",
            "Я понимаю невербальные сигналы других людей",
            "Я редко срываюсь эмоционально",
            "Я умею разрешать конфликты мирно",
            "Я осознаю влияние своих эмоций на решения"
        ]
        
        questions = []
        for text in question_texts:
            questions.append(EmotionalIntelligenceQuestion(text, self.standard_answers))
        return questions

    def get_questions(self) -> List[Dict]:
        """Returns list of questions for frontend."""
        formatted_questions = []
        for i, q in enumerate(self.questions):
            formatted_questions.append({
                'id': i + 1,
                'question': q.text,
                'options': q.options,
                'type': 'ei'
            })
        return formatted_questions

    def process_answers(self, answers: List[int]) -> Dict[str, any]:
        """Processes answers (list of 1-5 for each question), calculates EI score and interpretation."""
        if len(answers) != len(self.questions):
            raise ValueError(f"Expected {len(self.questions)} answers, got {len(answers)}.")

        # Map answers to scores (1=Never=1, 2=Rarely=2, 3=Sometimes=3, 4=Often=4, 5=Always=5)
        # But in Java it's 0-4 probably, adjust to 1-5 for consistency
        scores = [answer for answer in answers]  # Assuming answers are 1-5

        # Calculate total score
        total_score = sum(scores)
        
        # Normalize to 0-10 scale (max possible: 5 questions * 5 = 25, but we have 10, max 50)
        # In Java: totalScore / (size * 4) * 10, assuming 0-4 scale
        # Adjust: assuming 1-5 scale, max per question 5, so / (size * 5) * 10
        ei_score = (total_score / (len(answers) * 5)) * 10

        # Generate interpretation
        interpretation = self._generate_interpretation(ei_score)

        timestamp = int(datetime.now().timestamp() * 1000)

        return {
            'ei_score': round(ei_score, 1),
            'interpretation': interpretation,
            'timestamp': timestamp,
            # For compatibility
            'wellbeingScore': round(ei_score, 1),
            'activityScore': round(ei_score, 1),
            'moodScore': round(ei_score, 1)
        }

    def _generate_interpretation(self, ei_score: float) -> str:
        """Generates interpretation based on EI score."""
        interpretation = "РЕЗУЛЬТАТЫ ТЕСТА НА ЭМОЦИОНАЛЬНЫЙ ИНТЕЛЛЕКТ\n\n"
        interpretation += f"Уровень эмоционального интеллекта: {ei_score:.1f} из 10\n\n"

        if ei_score < 4:
            interpretation += "У вас низкий уровень эмоционального интеллекта. Вам может быть сложно распознавать и управлять своими эмоциями, а также понимать эмоции других людей.\n\n"
            interpretation += "Низкий эмоциональный интеллект может проявляться в следующем:\n"
            interpretation += "• Трудности в распознавании собственных эмоций\n"
            interpretation += "• Сложности в управлении эмоциональными реакциями\n"
            interpretation += "• Непонимание эмоций и мотивов других людей\n"
            interpretation += "• Проблемы в межличностных отношениях\n"
            interpretation += "• Трудности в адаптации к изменениям\n\n"
            
            interpretation += "Рекомендации для развития эмоционального интеллекта:\n"
            interpretation += "• Ведите дневник эмоций, записывая свои чувства и ситуации, которые их вызвали\n"
            interpretation += "• Развивайте навыки осознанности и самонаблюдения через медитацию\n"
            interpretation += "• Изучайте литературу по эмоциональному интеллекту\n"
            interpretation += "• Практикуйте активное слушание в общении с другими\n"
            interpretation += "• Обратите внимание на невербальные сигналы в общении\n"
            interpretation += "• Расширяйте свой эмоциональный словарь\n"
            interpretation += "• Рассмотрите возможность участия в тренингах по развитию эмоционального интеллекта\n"
            interpretation += "• Обратитесь к психологу для индивидуальной работы\n"
        elif ei_score < 7:
            interpretation += "У вас средний уровень эмоционального интеллекта. Вы обладаете определенными навыками распознавания и управления эмоциями, но есть потенциал для развития.\n\n"
            interpretation += "Средний эмоциональный интеллект характеризуется:\n"
            interpretation += "• Базовым пониманием собственных эмоций\n"
            interpretation += "• Способностью управлять эмоциями в большинстве ситуаций\n"
            interpretation += "• Умением распознавать основные эмоции других людей\n"
            interpretation += "• Относительно стабильными межличностными отношениями\n"
            interpretation += "• Способностью к эмпатии в очевидных ситуациях\n\n"
            
            interpretation += "Рекомендации для дальнейшего развития:\n"
            interpretation += "• Продолжайте развивать навыки эмпатии и активного слушания\n"
            interpretation += "• Практикуйте техники управления эмоциями в стрессовых ситуациях\n"
            interpretation += "• Обращайте больше внимания на невербальные сигналы в общении\n"
            interpretation += "• Развивайте навыки конструктивного выражения эмоций\n"
            interpretation += "• Учитесь распознавать более тонкие эмоциональные состояния\n"
            interpretation += "• Практикуйте рефлексию после эмоционально насыщенных ситуаций\n"
            interpretation += "• Развивайте навыки разрешения конфликтов\n"
        else:
            interpretation += "У вас высокий уровень эмоционального интеллекта. Вы хорошо понимаете свои и чужие эмоции, эффективно управляете ими и используете эту информацию для построения отношений и принятия решений.\n\n"
            interpretation += "Высокий эмоциональный интеллект проявляется в следующем:\n"
            interpretation += "• Глубокое понимание собственных эмоций и их причин\n"
            interpretation += "• Эффективное управление эмоциональными состояниями\n"
            interpretation += "• Способность точно распознавать эмоции других людей\n"
            interpretation += "• Развитая эмпатия и понимание мотивов поведения\n"
            interpretation += "• Успешные межличностные отношения\n"
            interpretation += "• Эффективное разрешение конфликтов\n"
            interpretation += "• Адаптивность к изменениям\n\n"
            
            interpretation += "Рекомендации для поддержания и дальнейшего развития:\n"
            interpretation += "• Делитесь своими знаниями и навыками с другими\n"
            interpretation += "• Продолжайте развивать эмоциональный интеллект в сложных ситуациях\n"
            interpretation += "• Используйте свои навыки для улучшения отношений и повышения эффективности в работе\n"
            interpretation += "• Рассмотрите возможность менторства или коучинга для других\n"
            interpretation += "• Изучайте более глубокие аспекты эмоционального интеллекта\n"
            interpretation += "• Практикуйте осознанность для поддержания эмоционального баланса\n"

        return interpretation

    def save_result(self, user_id: str, ei_score: float, interpretation: str) -> bool:
        """Saves result to Firebase."""
        if not user_id:
            raise ValueError("User ID is required.")

        timestamp = int(datetime.now().timestamp() * 1000)
        result_data = {
            'ei_score': ei_score,
            'interpretation': interpretation,
            'timestamp': timestamp,
            # For compatibility
            'wellbeingScore': ei_score,
            'activityScore': ei_score,
            'moodScore': ei_score
        }
        ref = db.reference(f'users/{user_id}/test_results/emotional_intelligence')
        new_ref = ref.push(result_data)
        return new_ref.key is not None