from typing import List, Dict
import firebase_admin
from firebase_admin import db
from datetime import datetime

from backend.services.test_results_service import save_test_result

class MaslachQuestion:
    def __init__(self, text: str, scale: str):
        self.text = text
        self.scale = scale  # 'exhaustion', 'depersonalization', 'accomplishment'

class TestResult:
    def __init__(self, exhaustion_score: int, depersonalization_score: int, accomplishment_score: int, 
                 interpretation: str, timestamp: int = None):
        self.exhaustion_score = exhaustion_score
        self.depersonalization_score = depersonalization_score
        self.accomplishment_score = accomplishment_score  # Note: this is inverted in scoring
        self.interpretation = interpretation
        self.timestamp = timestamp or int(datetime.now().timestamp() * 1000)

    def to_dict(self):
        # Normalize for compatibility (average inverted scores)
        avg_burnout = (self.exhaustion_score + self.depersonalization_score + (48 - self.accomplishment_score)) / 3 / 6.0 * 10
        return {
            'emotional_exhaustion': self.exhaustion_score,
            'depersonalization': self.depersonalization_score,
            'personal_accomplishment': self.accomplishment_score,
            'interpretation': self.interpretation,
            'timestamp': self.timestamp,
            # For compatibility - inverted burnout level
            'wellbeingScore': max(0, 10 - avg_burnout),
            'activityScore': max(0, 10 - avg_burnout),
            'moodScore': max(0, 10 - avg_burnout)
        }

class MaslachBurnoutService:
    def __init__(self):
        self.questions = self._initialize_questions()
        self.options = ["Никогда", "Очень редко", "Редко", "Иногда", "Часто", "Очень часто", "Ежедневно"]  # 0-6 scale

    def _initialize_questions(self) -> List[MaslachQuestion]:
        # Maslach Burnout Inventory: 22 questions
        # Exhaustion (9 items), Depersonalization (5 items), Accomplishment (8 items, reverse scored)
        questions_data = [
            # Emotional Exhaustion (0-8)
            ("Я чувствую себя эмоционально опустошенным", 'exhaustion'),
            ("К концу рабочего дня я чувствую себя как выжатый лимон", 'exhaustion'),
            ("Я чувствую себя усталым, когда встаю утром и должен идти на работу", 'exhaustion'),
            ("Работая с людьми, я чувствую, что эмоционально истощен", 'exhaustion'),
            ("Я чувствую, что у меня кончились эмоциональные и физические ресурсы", 'exhaustion'),
            ("Работа эмоционально истощает меня", 'exhaustion'),
            ("К концу дня я чувствую, что не могу больше терпеть", 'exhaustion'),
            ("Я чувствую, что работаю слишком много и слишком усердно", 'exhaustion'),
            ("Я чувствую, что работаю день и ночь", 'exhaustion'),
            
            # Depersonalization (9-13)
            ("Я стал более черствым по отношению к людям с тех пор, как начал эту работу", 'depersonalization'),
            ("Я переживаю, что эта работа делает меня эмоционально черствым", 'depersonalization'),
            ("Я стал равнодушным к людям, с которыми работаю", 'depersonalization'),
            ("Я не заботюсь о том, что происходит с людьми, с которыми работаю", 'depersonalization'),
            ("Я чувствую раздражение по отношению к людям, с которыми работаю", 'depersonalization'),
            
            # Personal Accomplishment (14-21, reverse scored)
            ("Я справляюсь с эмоциональными проблемами на работе", 'accomplishment'),
            ("Я чувствую, что эффективно решаю проблемы на работе", 'accomplishment'),
            ("Я чувствую эмоциональную и физическую энергию", 'accomplishment'),
            ("Я могу легко понять, что чувствуют мои коллеги", 'accomplishment'),
            ("Я справляюсь с проблемами на работе", 'accomplishment'),
            ("Я чувствую, что вношу ценный вклад в работу", 'accomplishment'),
            ("Я имею много энтузиазма по поводу моей работы", 'accomplishment'),
            ("Я чувствую, что у меня есть энергия для работы с людьми", 'accomplishment')
        ]
        
        return [MaslachQuestion(text, scale) for text, scale in questions_data]

    def get_questions(self) -> List[Dict]:
        """Returns list of questions for frontend."""
        formatted_questions = []
        for i, q in enumerate(self.questions):
            formatted_questions.append({
                'id': i + 1,
                'question': q.text,
                'options': self.options,
                'type': 'maslach',
                'scale': q.scale
            })
        return formatted_questions

    def process_answers(self, answers: List[int]) -> Dict[str, any]:
        """Processes answers (list of 0-6 for each of 22 questions), calculates scores per scale."""
        if len(answers) != 22:
            raise ValueError("Maslach Burnout Inventory requires exactly 22 answers.")

        # Emotional Exhaustion (questions 0-8)
        exhaustion_score = sum(answers[0:9])

        # Depersonalization (questions 9-13)
        depersonalization_score = sum(answers[9:14])

        # Personal Accomplishment (questions 14-21, reverse scored: 48 - sum)
        accomplishment_sum = sum(answers[14:22])
        accomplishment_score = 48 - accomplishment_sum  # Reverse scoring

        # Generate interpretation
        interpretation = self._generate_interpretation(exhaustion_score, depersonalization_score, accomplishment_score)

        timestamp = int(datetime.now().timestamp() * 1000)

        return {
            'exhaustion_score': exhaustion_score,
            'depersonalization_score': depersonalization_score,
            'accomplishment_score': accomplishment_score,
            'interpretation': interpretation,
            'timestamp': timestamp,
            # For compatibility
            'wellbeingScore': max(0, 10 - ((exhaustion_score + depersonalization_score + (48 - accomplishment_score)) / 3 / 6.0 * 10)),
            'activityScore': max(0, 10 - ((exhaustion_score + depersonalization_score + (48 - accomplishment_score)) / 3 / 6.0 * 10)),
            'moodScore': max(0, 10 - ((exhaustion_score + depersonalization_score + (48 - accomplishment_score)) / 3 / 6.0 * 10))
        }

    def _generate_interpretation(self, exhaustion: int, deperson: int, accomp: int) -> str:
        """Generates interpretation based on Maslach scores."""
        interpretation = "РЕЗУЛЬТАТЫ ТЕСТА НА ПРОФЕССИОНАЛЬНОЕ ВЫГОРАНИЕ (МЕТОДИКА К. МАСЛАЧ)\n\n"

        # Exhaustion
        interpretation += f"Эмоциональное истощение: {exhaustion} баллов\n"
        if exhaustion <= 15:
            interpretation += "Низкий уровень эмоционального истощения\n"
        elif exhaustion <= 24:
            interpretation += "Средний уровень эмоционального истощения\n"
        else:
            interpretation += "Высокий уровень эмоционального истощения\n"

        # Depersonalization
        interpretation += f"\nДеперсонализация: {deperson} баллов\n"
        if deperson <= 5:
            interpretation += "Низкий уровень деперсонализации\n"
        elif deperson <= 10:
            interpretation += "Средний уровень деперсонализации\n"
        else:
            interpretation += "Высокий уровень деперсонализации\n"

        # Accomplishment (note: higher is better, but scored as reduction)
        interpretation += f"\nРедукция профессиональных достижений: {48 - accomp} баллов (личное достижение: {accomp})\n"
        if accomp >= 32:  # High accomplishment (low reduction)
            interpretation += "Низкий уровень редукции профессиональных достижений\n"
        elif accomp >= 17:
            interpretation += "Средний уровень редукции профессиональных достижений\n"
        else:
            interpretation += "Высокий уровень редукции профессиональных достижений\n"

        # Overall
        interpretation += "\nОБЩАЯ ИНТЕРПРЕТАЦИЯ:\n"
        high_burnout = exhaustion > 24 or deperson > 10 or accomp < 17
        if exhaustion > 24 and deperson > 10 and accomp < 17:
            interpretation += "У вас высокий уровень профессионального выгорания по всем трем компонентам. Это серьезное состояние, требующее профессиональной помощи и значительных изменений в профессиональной деятельности.\n"
        elif high_burnout:
            interpretation += "У вас наблюдаются признаки профессионального выгорания по одному или нескольким компонентам. Рекомендуется обратить внимание на свое психологическое состояние и принять меры по его улучшению.\n"
        else:
            interpretation += "У вас низкий или средний уровень профессионального выгорания. Рекомендуется поддерживать баланс между работой и отдыхом для профилактики выгорания.\n"

        # Recommendations
        interpretation += "\nРЕКОМЕНДАЦИИ:\n"
        if exhaustion > 15:
            interpretation += "Для снижения эмоционального истощения:\n"
            interpretation += "- Выделяйте время для полноценного отдыха и восстановления\n"
            interpretation += "- Практикуйте техники релаксации и медитации\n"
            interpretation += "- Обратитесь за поддержкой к коллегам или близким\n"

        if deperson > 5:
            interpretation += "\nДля снижения деперсонализации:\n"
            interpretation += "- Развивайте эмпатию и навыки коммуникации\n"
            interpretation += "- Участвуйте в групповых мероприятиях и тренингах\n"
            interpretation += "- Ищите смысл и ценность в своей работе\n"

        if accomp < 32:
            interpretation += "\nДля повышения профессиональной эффективности:\n"
            interpretation += "- Ставьте реалистичные цели и отмечайте достижения\n"
            interpretation += "- Развивайте профессиональные навыки\n"
            interpretation += "- Ищите новые подходы и методы в работе\n"

        return interpretation

    def save_result(self, user_id: str, exhaustion: int, deperson: int, accomp: int, interpretation: str) -> bool:
        """Saves result to Firebase."""
        if not user_id:
            raise ValueError("User ID is required.")

        timestamp = int(datetime.now().timestamp() * 1000)
        burnout_level = (exhaustion + deperson + (48 - accomp)) / 3 / 6.0 * 10
        result_data = {
            'exhaustion_score': exhaustion,
            'depersonalization_score': deperson,
            'accomplishment_score': accomp,
            'interpretation': interpretation,
            'timestamp': timestamp,
            'wellbeingScore': max(0, 10 - burnout_level),
            'activityScore': max(0, 10 - burnout_level),
            'moodScore': max(0, 10 - burnout_level)
        }
        return save_test_result(user_id, "maslach_burnout", result_data)
