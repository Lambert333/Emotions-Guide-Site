from typing import List, Dict
import firebase_admin
from firebase_admin import db
from datetime import datetime

class BoykoQuestion:
    def __init__(self, text: str, phase: str, symptom: str):
        self.text = text
        self.phase = phase  # 'tension', 'resistance', 'exhaustion'
        self.symptom = symptom  # specific symptom name

class TestResult:
    def __init__(self, total_score: int, tension_score: int, resistance_score: int, exhaustion_score: int, 
                 interpretation: str, timestamp: int = None):
        self.total_score = total_score
        self.tension_score = tension_score
        self.resistance_score = resistance_score
        self.exhaustion_score = exhaustion_score
        self.interpretation = interpretation
        self.timestamp = timestamp or int(datetime.now().timestamp() * 1000)

    def to_dict(self):
        # Normalize to 0-10 (inverted: low burnout = high score)
        normalized_score = 10 - (self.total_score / 360.0 * 10)
        return {
            'total_burnout_score': self.total_score,
            'tension_phase': self.tension_score,
            'resistance_phase': self.resistance_score,
            'exhaustion_phase': self.exhaustion_score,
            'interpretation': self.interpretation,
            'timestamp': self.timestamp,
            # For compatibility
            'wellbeingScore': max(0, normalized_score),
            'activityScore': max(0, normalized_score),
            'moodScore': max(0, normalized_score)
        }

class BoykoBurnoutService:
    def __init__(self):
        self.standard_answers = ["Никогда", "Редко", "Иногда", "Часто", "Всегда"]  # 1-5 scale
        self.questions = self._initialize_questions()

    def _initialize_questions(self) -> List[BoykoQuestion]:
        # Based on Java structure: 84 questions, 3 phases, 4 symptoms per phase, 7 questions per symptom
        # Questions are examples from Java comments; in real implementation, full validated questions needed
        phases = {
            'tension': {
                'traumatic_circumstances': [
                    "Я чувствую себя эмоционально опустошенным к концу рабочего дня",
                    "Я замечаю, что стал более черствым по отношению к людям",
                    "Меня тревожат мысли о работе",
                    "Я чувствую, что моя работа эмоционально истощает меня",
                    "Я замечаю, что стал более раздражительным",
                    "Я чувствую себя на пределе возможностей",
                    "Я чувствую разочарование в своей работе"
                ],
                'self_dissatisfaction': [
                    "Я недоволен собой на работе",
                    "Я чувствую, что недостаточно компетентен в своей работе",
                    "Я не удовлетворен своими профессиональными достижениями",
                    "Я сомневаюсь в значимости своей работы",
                    "Я чувствую, что мог бы сделать больше на своей работе",
                    "Я думаю, что выбрал неправильную профессию",
                    "Я чувствую, что моя работа не приносит пользы"
                ],
                'cagedness': [
                    "Я чувствую себя загнанным в тупик",
                    "Я не вижу выхода из сложившейся ситуации",
                    "Я чувствую, что не могу изменить ситуацию на работе",
                    "Я ощущаю безвыходность ситуации",
                    "Я чувствую себя пойманным в ловушку обстоятельств",
                    "Я ощущаю бессилие что-либо изменить",
                    "Я чувствую, что нахожусь в тупике"
                ],
                'anxiety_depression': [
                    "Я испытываю тревогу без видимой причины",
                    "У меня бывает подавленное настроение",
                    "Я чувствую беспокойство по поводу своей работы",
                    "Я испытываю чувство безнадежности",
                    "Я замечаю у себя признаки депрессии",
                    "Меня беспокоят мысли о будущем",
                    "Я чувствую себя подавленным"
                ]
            },
            'resistance': {
                'inadequate_emotional_response': [
                    "Я стал более холодным в общении с коллегами",
                    "Я замечаю, что стал избирательно реагировать на ситуации",
                    "Я стараюсь избегать эмоционально напряженных ситуаций",
                    "Я замечаю, что стал более равнодушным к проблемам других",
                    "Я стал более формально выполнять свои обязанности",
                    "Я стараюсь сократить время общения с коллегами",
                    "Я замечаю, что стал более черствым в общении"
                ],
                # Add other resistance symptoms with 7 questions each (placeholders for now)
                'emotional_moral_disorientation': ["Placeholder question 1 for emotional disorientation"] * 7,
                'emotional_economy': ["Placeholder question 1 for emotional economy"] * 7,
                'professional_reduction': ["Placeholder question 1 for professional reduction"] * 7
            },
            'exhaustion': {
                'emotional_deficit': ["Placeholder question 1 for emotional deficit"] * 7,
                'emotional_detachment': ["Placeholder question 1 for emotional detachment"] * 7,
                'personal_detachment': ["Placeholder question 1 for personal detachment"] * 7,
                'psychosomatic_disorders': ["Placeholder question 1 for psychosomatic disorders"] * 7
            }
        }

        questions = []
        for phase, symptoms in phases.items():
            for symptom, texts in symptoms.items():
                for i, text in enumerate(texts):
                    questions.append(BoykoQuestion(text, phase, symptom))
        
        # Ensure exactly 84 questions
        while len(questions) < 84:
            questions.append(BoykoQuestion("Дополнительный вопрос для полноты теста", 'exhaustion', 'psychosomatic_disorders'))
        
        return questions[:84]

    def get_questions(self) -> List[Dict]:
        """Returns list of questions for frontend."""
        formatted_questions = []
        for i, q in enumerate(self.questions):
            formatted_questions.append({
                'id': i + 1,
                'question': q.text,
                'options': self.standard_answers,
                'type': 'boyko',
                'phase': q.phase,
                'symptom': q.symptom
            })
        return formatted_questions

    def process_answers(self, answers: List[int]) -> Dict[str, any]:
        """Processes answers (list of 1-5 for each of 84 questions), calculates scores per phase/symptom and total."""
        if len(answers) != 84:
            raise ValueError("Boyko test requires exactly 84 answers.")

        # Calculate scores per symptom (7 questions each)
        symptom_scores = {}
        phase_scores = {'tension': 0, 'resistance': 0, 'exhaustion': 0}
        
        # Define symptom ranges (0-based indices)
        symptoms_ranges = {
            'tension_traumatic': (0, 7),
            'tension_self_dissatisfaction': (7, 14),
            'tension_cagedness': (14, 21),
            'tension_anxiety_depression': (21, 28),
            'resistance_inadequate': (28, 35),
            'resistance_emotional_disorientation': (35, 42),
            'resistance_economy': (42, 49),
            'resistance_professional': (49, 56),
            'exhaustion_deficit': (56, 63),
            'exhaustion_detachment': (63, 70),
            'exhaustion_personal': (70, 77),
            'exhaustion_psychosomatic': (77, 84)
        }

        for symptom, (start, end) in symptoms_ranges.items():
            scores = answers[start:end]
            symptom_score = sum(scores)
            symptom_scores[symptom] = symptom_score
            phase = symptom.split('_')[0]
            phase_scores[phase] += symptom_score

        total_score = sum(phase_scores.values())

        # Generate interpretation
        interpretation = self._generate_interpretation(total_score, phase_scores, symptom_scores)

        timestamp = int(datetime.now().timestamp() * 1000)

        return {
            'total_score': total_score,
            'tension_score': phase_scores['tension'],
            'resistance_score': phase_scores['resistance'],
            'exhaustion_score': phase_scores['exhaustion'],
            'interpretation': interpretation,
            'timestamp': timestamp,
            # For compatibility
            'wellbeingScore': max(0, 10 - (total_score / 360.0 * 10)),
            'activityScore': max(0, 10 - (total_score / 360.0 * 10)),
            'moodScore': max(0, 10 - (total_score / 360.0 * 10))
        }

    def _generate_interpretation(self, total_score: int, phase_scores: Dict, symptom_scores: Dict) -> str:
        """Generates detailed interpretation based on Boyko methodology."""
        interpretation = "РЕЗУЛЬТАТЫ ТЕСТА НА ЭМОЦИОНАЛЬНОЕ ВЫГОРАНИЕ (МЕТОДИКА В.В. БОЙКО)\n\n"
        interpretation += f"Общий уровень эмоционального выгорания: {total_score} баллов\n\n"

        # Overall level
        if total_score < 50:
            interpretation += "У вас отсутствует эмоциональное выгорание. Вы эффективно справляетесь с профессиональными стрессами.\n\n"
        elif total_score < 100:
            interpretation += "У вас начальная стадия эмоционального выгорания. Обратите внимание на свое эмоциональное состояние и примите меры профилактики.\n\n"
        elif total_score < 150:
            interpretation += "У вас формирующееся эмоциональное выгорание. Необходимо принять меры по снижению стресса и восстановлению эмоционального равновесия.\n\n"
        else:
            interpretation += "У вас сформировавшееся эмоциональное выгорание. Рекомендуется обратиться к специалисту для получения профессиональной помощи.\n\n"

        # Phase analysis
        interpretation += "АНАЛИЗ ПО ФАЗАМ ЭМОЦИОНАЛЬНОГО ВЫГОРАНИЯ:\n\n"

        for phase, score in phase_scores.items():
            phase_name = {'tension': 'Напряжение', 'resistance': 'Резистенция', 'exhaustion': 'Истощение'}[phase]
            interpretation += f"1. Фаза \"{phase_name}\": {score} баллов\n"
            if score < 37:
                interpretation += "Фаза не сформировалась\n"
            elif score < 60:
                interpretation += "Фаза в стадии формирования\n"
            else:
                interpretation += "Фаза сформировалась\n"

            # Symptom details for this phase (simplified)
            interpretation += f"   - Основные симптомы фазы: средний балл {score/4:.1f}\n"

        # Recommendations
        interpretation += "\nРЕКОМЕНДАЦИИ ПО ПРОФИЛАКТИКЕ И ПРЕОДОЛЕНИЮ ЭМОЦИОНАЛЬНОГО ВЫГОРАНИЯ:\n\n"

        if total_score < 50:
            interpretation += "Для поддержания эмоционального благополучия:\n"
            interpretation += "• Продолжайте поддерживать баланс между работой и отдыхом\n"
            interpretation += "• Регулярно практикуйте техники релаксации и управления стрессом\n"
            interpretation += "• Уделяйте время физической активности и хобби\n"
            interpretation += "• Поддерживайте социальные связи и общение с близкими\n"
        elif total_score < 100:
            interpretation += "Для профилактики развития выгорания:\n"
            interpretation += "• Пересмотрите свой режим труда и отдыха\n"
            interpretation += "• Выделите время для восстановления эмоциональных ресурсов\n"
            interpretation += "• Практикуйте техники релаксации (медитация, глубокое дыхание)\n"
            interpretation += "• Обратите внимание на качество сна\n"
            interpretation += "• Занимайтесь физическими упражнениями\n"
            interpretation += "• Развивайте навыки тайм-менеджмента\n"
        elif total_score < 150:
            interpretation += "Для преодоления формирующегося выгорания:\n"
            interpretation += "• Обратитесь к психологу для консультации\n"
            interpretation += "• Пересмотрите свои профессиональные цели и приоритеты\n"
            interpretation += "• Освойте техники управления стрессом\n"
            interpretation += "• Временно снизьте рабочую нагрузку, если это возможно\n"
            interpretation += "• Уделите особое внимание физическому здоровью\n"
            interpretation += "• Практикуйте осознанность и принятие своих эмоций\n"
            interpretation += "• Найдите источники эмоциональной поддержки\n"
        else:
            interpretation += "Для преодоления сформировавшегося выгорания:\n"
            interpretation += "• Обратитесь к психотерапевту или психологу для профессиональной помощи\n"
            interpretation += "• Рассмотрите возможность временного отпуска или снижения нагрузки\n"
            interpretation += "• Пересмотрите свои жизненные и профессиональные ценности\n"
            interpretation += "• Практикуйте регулярные техники восстановления (медитация, релаксация)\n"
            interpretation += "• Обеспечьте полноценный отдых и сон\n"
            interpretation += "• Обратите внимание на питание и физическую активность\n"
            interpretation += "• Найдите новые источники вдохновения и мотивации\n"

        return interpretation

    def save_result(self, user_id: str, total_score: int, tension: int, resistance: int, exhaustion: int, interpretation: str) -> bool:
        """Saves result to Firebase."""
        if not user_id:
            raise ValueError("User ID is required.")

        timestamp = int(datetime.now().timestamp() * 1000)
        normalized_score = 10 - (total_score / 360.0 * 10)
        result_data = {
            'total_score': total_score,
            'tension_score': tension,
            'resistance_score': resistance,
            'exhaustion_score': exhaustion,
            'interpretation': interpretation,
            'timestamp': timestamp,
            'wellbeingScore': max(0, normalized_score),
            'activityScore': max(0, normalized_score),
            'moodScore': max(0, normalized_score)
        }
        ref = db.reference(f'users/{user_id}/test_results/boyko_burnout')
        new_ref = ref.push(result_data)
        return new_ref.key is not None