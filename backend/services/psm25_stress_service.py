from typing import List, Dict
import firebase_admin
from firebase_admin import db
from datetime import datetime

class PSM25Question:
    def __init__(self, text: str, options: List[str]):
        self.text = text
        self.options = options

class TestResult:
    def __init__(self, total_score: int, interpretation: str, timestamp: int = None):
        self.total_score = total_score
        self.interpretation = interpretation
        self.timestamp = timestamp or int(datetime.now().timestamp() * 1000)

    def to_dict(self):
        return {
            'total_score': self.total_score,
            'interpretation': self.interpretation,
            'timestamp': self.timestamp,
            # For compatibility
            'wellbeingScore': 10 - (self.total_score / 154.0 * 10) if self.total_score <= 154 else 0,
            'activityScore': 10 - (self.total_score / 154.0 * 10) if self.total_score <= 154 else 0,
            'moodScore': 10 - (self.total_score / 154.0 * 10) if self.total_score <= 154 else 0
        }

class PSM25StressService:
    def __init__(self):
        self.standard_answers = ["Никогда", "Редко", "Иногда", "Часто", "Всегда"]
        self.questions = self._initialize_questions()

    def _initialize_questions(self) -> List[PSM25Question]:
        # Standard PSM-25 questions (25 items)
        question_texts = [
            "Я чувствую себя измотанным",
            "Я чувствую, что мне не с кем поговорить",
            "Я чувствую себя подавленным",
            "Я чувствую себя напряженным",
            "Я чувствую, что многие люди меня не любят",
            "Я чувствую себя в тупике",
            "Я испытываю головные боли",
            "Я чувствую себя беспомощным",
            "Я не могу избавиться от навязчивых мыслей",
            "Я легко утомляюсь",
            "Я чувствую, что никому не могу доверять",
            "Я легко раздражаюсь",
            "Я чувствую себя разбитым",
            "Я чувствую печаль",
            "Я чувствую, что я никому не нужен",
            "Я чувствую, что запутался в своей жизни",
            "Я испытываю мышечное напряжение",
            "У меня проблемы со сном",
            "Я чувствую безнадежность",
            "Я чувствую себя неудачником",
            "Я чувствую себя в ловушке",
            "Я чувствую себя никчемным",
            "Я чувствую, что люди недружелюбны ко мне",
            "Я чувствую, что жизнь несправедлива",
            "Я чувствую, что не могу продолжать дальше"
        ]
        
        questions = []
        for text in question_texts:
            questions.append(PSM25Question(text, self.standard_answers))
        return questions

    def get_questions(self) -> List[Dict]:
        """Returns list of questions for frontend."""
        formatted_questions = []
        for i, q in enumerate(self.questions):
            formatted_questions.append({
                'id': i + 1,
                'question': q.text,
                'options': q.options,
                'type': 'psm25'
            })
        return formatted_questions

    def process_answers(self, answers: List[int]) -> Dict[str, any]:
        """Processes answers (list of 1-5 for each of 25 questions), calculates total score and interpretation."""
        if len(answers) != 25:
            raise ValueError("PSM-25 requires exactly 25 answers.")

        # Scores: Never=1, Rarely=2, Sometimes=3, Often=4, Always=5
        total_score = sum(answers)

        # Generate interpretation
        interpretation = self._generate_interpretation(total_score)

        timestamp = int(datetime.now().timestamp() * 1000)

        return {
            'total_score': total_score,
            'interpretation': interpretation,
            'timestamp': timestamp,
            # For compatibility - normalize to 0-10 (inverted: low stress = high score)
            'wellbeingScore': max(0, 10 - (total_score / 154.0 * 10)),
            'activityScore': max(0, 10 - (total_score / 154.0 * 10)),
            'moodScore': max(0, 10 - (total_score / 154.0 * 10))
        }

    def _generate_interpretation(self, total_score: int) -> str:
        """Generates interpretation based on PSM-25 total score."""
        interpretation = "РЕЗУЛЬТАТЫ ТЕСТА PSM-25 (ШКАЛА ПСИХОЛОГИЧЕСКОГО СТРЕССА)\n\n"
        interpretation += f"Общий балл: {total_score}\n\n"

        if total_score <= 99:
            interpretation += "Низкий уровень стресса. Состояние психологической адаптированности к рабочим нагрузкам.\n\n"
            interpretation += "Рекомендации:\n"
            interpretation += "- Поддерживайте текущий баланс между работой и отдыхом\n"
            interpretation += "- Продолжайте практиковать эффективные стратегии управления стрессом\n"
            interpretation += "- Регулярно занимайтесь физическими упражнениями для поддержания хорошего самочувствия\n"
        elif total_score <= 154:
            interpretation += "Средний уровень стресса. Умеренный уровень психологического напряжения.\n\n"
            interpretation += "Рекомендации:\n"
            interpretation += "- Обратите внимание на факторы, вызывающие стресс, и постарайтесь их минимизировать\n"
            interpretation += "- Практикуйте техники релаксации (глубокое дыхание, медитация, прогрессивная мышечная релаксация)\n"
            interpretation += "- Уделяйте достаточно времени для отдыха и восстановления\n"
            interpretation += "- Поддерживайте здоровый образ жизни (сон, питание, физическая активность)\n"
        else:
            interpretation += "Высокий уровень стресса. Состояние дезадаптации и психологического дискомфорта, требующее применения широкого спектра средств и методов для снижения нервно-психической напряженности.\n\n"
            interpretation += "Рекомендации:\n"
            interpretation += "- Обратитесь к психологу или психотерапевту для профессиональной помощи\n"
            interpretation += "- Пересмотрите свой режим дня и рабочую нагрузку\n"
            interpretation += "- Освойте и регулярно практикуйте техники управления стрессом\n"
            interpretation += "- Уделяйте особое внимание качеству сна и отдыха\n"
            interpretation += "- Обратитесь за поддержкой к близким людям\n"
            interpretation += "- Рассмотрите возможность временного снижения рабочей нагрузки\n"

        return interpretation

    def save_result(self, user_id: str, total_score: int, interpretation: str) -> bool:
        """Saves result to Firebase."""
        if not user_id:
            raise ValueError("User ID is required.")

        timestamp = int(datetime.now().timestamp() * 1000)
        normalized_score = max(0, 10 - (total_score / 154.0 * 10))
        result_data = {
            'total_score': total_score,
            'interpretation': interpretation,
            'timestamp': timestamp,
            'wellbeingScore': normalized_score,
            'activityScore': normalized_score,
            'moodScore': normalized_score
        }
        ref = db.reference(f'users/{user_id}/test_results/psm25_stress')
        new_ref = ref.push(result_data)
        return new_ref.key is not None