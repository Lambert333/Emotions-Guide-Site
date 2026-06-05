from typing import List, Dict
import firebase_admin
from firebase_admin import db
from datetime import datetime

from backend.services.test_results_service import save_test_result

class SelfEsteemQuestion:
    def __init__(self, text: str, is_reverse: bool = True):
        self.text = text
        self.is_reverse = is_reverse  # Most self-esteem questions are reverse scored

class TestResult:
    def __init__(self, self_esteem_score: float, interpretation: str, timestamp: int = None):
        self.self_esteem_score = self_esteem_score
        self.interpretation = interpretation
        self.timestamp = timestamp or int(datetime.now().timestamp() * 1000)

    def to_dict(self):
        return {
            'self_esteem_score': self.self_esteem_score,
            'interpretation': self.interpretation,
            'timestamp': self.timestamp,
            # For compatibility
            'wellbeingScore': self.self_esteem_score / 10,  # Normalize to 0-10
            'activityScore': self.self_esteem_score / 10,
            'moodScore': self.self_esteem_score / 10
        }

class SelfEsteemService:
    def __init__(self):
        self.questions = self._initialize_questions()
        self.options = ["Очень часто", "Часто", "Иногда", "Редко", "Никогда"]  # 5-1 scoring, reverse

    def _initialize_questions(self) -> List[SelfEsteemQuestion]:
        # Dembo-Rubinstein self-esteem test questions (15 items, all reverse scored)
        question_texts = [
            "Я часто волнуюсь понапрасну",
            "Мне хочется, чтобы мои друзья подбадривали меня",
            "Я боюсь выглядеть глупцом",
            "Я беспокоюсь за свое будущее",
            "Внешний вид других куда лучше, чем мой",
            "Как жаль, что многие не понимают меня",
            "Чувствую, что не умею как следует разговаривать с людьми",
            "Люди ждут от меня очень многого",
            "Чувствую себя скованным",
            "Мне кажется, что со мной должна случиться какая-нибудь неприятность",
            "Меня волнует мысль о том, как люди относятся ко мне",
            "Я чувствую, что люди говорят обо мне за моей спиной",
            "Я не чувствую себя в безопасности",
            "Мне не с кем поделиться своими мыслями",
            "Люди не особенно интересуются моими достижениями"
        ]
        
        return [SelfEsteemQuestion(text, True) for text in question_texts]  # All reverse scored

    def get_questions(self) -> List[Dict]:
        """Returns list of questions for frontend."""
        formatted_questions = []
        for i, q in enumerate(self.questions):
            formatted_questions.append({
                'id': i + 1,
                'question': q.text,
                'options': self.options,
                'type': 'self_esteem',
                'reverse': q.is_reverse
            })
        return formatted_questions

    def process_answers(self, answers: List[int]) -> Dict[str, any]:
        """Processes answers (list of 1-5 where 1=Very Often=low self-esteem, 5=Never=high), 
        reverse scores, calculates total and normalized score."""
        if len(answers) != 15:
            raise ValueError("Self-Esteem test requires exactly 15 answers.")

        # Reverse scoring: Very Often (1) -> 1 (low), Never (5) -> 5 (high)
        # But since all are reverse, score as is: higher answer = higher self-esteem
        # In Java: total / size * 25 for 0-100 (assuming 0-4 scale, but adjust)
        # Assuming answers 1-5, total max 75, so total / 75 * 100

        total_score = sum(answers)
        self_esteem_score = (total_score / 75.0) * 100  # 0-100 scale

        # Generate interpretation
        interpretation = self._generate_interpretation(self_esteem_score)

        timestamp = int(datetime.now().timestamp() * 1000)

        return {
            'self_esteem_score': round(self_esteem_score, 1),
            'interpretation': interpretation,
            'timestamp': timestamp,
            # For compatibility 0-10
            'wellbeingScore': round(self_esteem_score / 10, 1),
            'activityScore': round(self_esteem_score / 10, 1),
            'moodScore': round(self_esteem_score / 10, 1)
        }

    def _generate_interpretation(self, score: float) -> str:
        """Generates interpretation based on self-esteem score (0-100)."""
        interpretation = "РЕЗУЛЬТАТЫ ТЕСТА НА САМООЦЕНКУ (МЕТОДИКА ДЕМБО-РУБИНШТЕЙН)\n\n"
        interpretation += f"Уровень самооценки: {score:.1f} из 100\n\n"

        if score <= 40:
            interpretation += "Заниженная самооценка. Вы склонны недооценивать свои способности, достижения и личностные качества.\n\n"
            interpretation += "Заниженная самооценка может быть связана с неуверенностью в себе, повышенной самокритичностью, негативным опытом в прошлом или сравнением себя с другими. Люди с заниженной самооценкой часто испытывают трудности в принятии решений, боятся неудач и избегают новых вызовов.\n\n"
            interpretation += "Рекомендации:\n"
            interpretation += "- Ведите дневник успехов, записывая даже небольшие достижения\n"
            interpretation += "- Практикуйте позитивные утверждения (аффирмации)\n"
            interpretation += "- Перестаньте сравнивать себя с другими\n"
            interpretation += "- Окружите себя поддерживающими людьми\n"
            interpretation += "- Ставьте реалистичные цели и отмечайте прогресс\n"
            interpretation += "- Развивайте навыки и таланты в интересующих вас областях\n"
            interpretation += "- При необходимости обратитесь к психологу для работы над самооценкой\n"
        elif score <= 70:
            interpretation += "Адекватная (средняя) самооценка. Вы реалистично оцениваете свои способности, достижения и личностные качества.\n\n"
            interpretation += "Адекватная самооценка характеризуется здоровым балансом между уверенностью в себе и самокритичностью. Люди с адекватной самооценкой принимают себя такими, какие они есть, осознают свои сильные и слабые стороны, способны принимать конструктивную критику и учиться на ошибках.\n\n"
            interpretation += "Рекомендации:\n"
            interpretation += "- Продолжайте развиваться в интересующих вас областях\n"
            interpretation += "- Поддерживайте баланс между самопринятием и стремлением к росту\n"
            interpretation += "- Регулярно анализируйте свои достижения и ставьте новые цели\n"
            interpretation += "- Практикуйте благодарность и осознанность\n"
            interpretation += "- Поддерживайте здоровые отношения с окружающими\n"
        else:
            interpretation += "Завышенная самооценка. Вы склонны переоценивать свои способности, достижения и личностные качества.\n\n"
            interpretation += "Завышенная самооценка может проявляться в чрезмерной уверенности в себе, нереалистичных ожиданиях, трудностях в принятии критики и признании своих ошибок. Люди с завышенной самооценкой могут испытывать проблемы в общении, так как часто не учитывают мнения и чувства других людей.\n\n"
            interpretation += "Рекомендации:\n"
            interpretation += "- Развивайте навыки рефлексии и самоанализа\n"
            interpretation += "- Учитесь принимать конструктивную критику\n"
            interpretation += "- Практикуйте эмпатию и активное слушание\n"
            interpretation += "- Ставьте реалистичные цели и планы\n"
            interpretation += "- Признавайте свои ошибки и учитесь на них\n"
            interpretation += "- Развивайте навыки сотрудничества и командной работы\n"

        return interpretation

    def save_result(self, user_id: str, score: float, interpretation: str) -> bool:
        """Saves result to Firebase."""
        if not user_id:
            raise ValueError("User ID is required.")

        timestamp = int(datetime.now().timestamp() * 1000)
        normalized_score = score / 10
        result_data = {
            'self_esteem_score': score,
            'interpretation': interpretation,
            'timestamp': timestamp,
            'wellbeingScore': normalized_score,
            'activityScore': normalized_score,
            'moodScore': normalized_score
        }
        return save_test_result(user_id, "self_esteem", result_data)
