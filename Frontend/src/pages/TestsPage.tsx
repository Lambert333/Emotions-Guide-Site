import React, { useState, useEffect } from "react";
import {
  TestTube,
  Brain,
  CheckCircle,
  XCircle,
  BarChart3,
  Heart,
  AlertTriangle,
  Zap,
  Smile,
  Activity,
  Award,
} from "lucide-react";
import { testsAPI } from "../services/api";

interface TestQuestion {
  id: number;
  question: string;
  options: string[];
  type?: string;
  scale?: string;
  affect_type?: string;
  reverse?: boolean;
  phase?: string;
  symptom?: string;
}

interface TestResult {
  wellbeing: number;
  activity: number;
  mood: number;
  timestamp: number;
  interpretation: string;
  // Additional fields for specific tests
  ei_score?: number;
  total_score?: number;
  situational_anxiety?: number;
  personal_anxiety?: number;
  tension_score?: number;
  resistance_score?: number;
  exhaustion_score?: number;
  depersonalization_score?: number;
  accomplishment_score?: number;
  self_esteem_score?: number;
  positive_affect?: number;
  negative_affect?: number;
  mood_balance?: number;
}

interface ScoreDisplay {
  key: string;
  label: string;
  value: number;
  type?: string;
  reverse?: boolean;
}

interface ScoreDisplay {
  key: string;
  label: string;
  value: number;
  type?: string;
  reverse?: boolean;
}

interface TestInfo {
  id: string;
  title: string;
  description: string;
  icon: React.ReactNode;
  questionCount: number;
  apiPrefix: string;
  resultFields: string[];
}

const availableTests: TestInfo[] = [
  {
    id: "san",
    title: "Тест САН",
    description: "Самочувствие, Активность, Настроение (30 вопросов)",
    icon: <Activity size={20} />,
    questionCount: 30,
    apiPrefix: "san",
    resultFields: ["wellbeing", "activity", "mood"],
  },
  {
    id: "emotional_intelligence",
    title: "Эмоциональный интеллект",
    description:
      "Оценка способности понимать и управлять эмоциями (10 вопросов)",
    icon: <Heart size={20} />,
    questionCount: 10,
    apiPrefix: "emotional_intelligence",
    resultFields: ["ei_score"],
  },
  {
    id: "psm25_stress",
    title: "Тест на стресс PSM-25",
    description: "Шкала психологического стресса (25 вопросов)",
    icon: <AlertTriangle size={20} />,
    questionCount: 25,
    apiPrefix: "psm25_stress",
    resultFields: ["total_score"],
  },
  {
    id: "spielberger_anxiety",
    title: "Тест на тревожность",
    description:
      "Спилберг-Ханин: ситуативная и личностная тревожность (40 вопросов)",
    icon: <Zap size={20} />,
    questionCount: 40,
    apiPrefix: "spielberger_anxiety",
    resultFields: ["situational_anxiety", "personal_anxiety"],
  },
  {
    id: "boyko_burnout",
    title: "Тест на выгорание (Бойко)",
    description: "Диагностика эмоционального выгорания (84 вопроса)",
    icon: <Award size={20} />,
    questionCount: 84,
    apiPrefix: "boyko_burnout",
    resultFields: [
      "total_score",
      "tension_score",
      "resistance_score",
      "exhaustion_score",
    ],
  },
  {
    id: "maslach_burnout",
    title: "Тест на выгорание (Маслач)",
    description: "Профессиональное выгорание по Маслач (22 вопроса)",
    icon: <Award size={20} />,
    questionCount: 22,
    apiPrefix: "maslach_burnout",
    resultFields: [
      "exhaustion_score",
      "depersonalization_score",
      "accomplishment_score",
    ],
  },
  {
    id: "self_esteem",
    title: "Тест на самооценку",
    description: "Методика Дембо-Рубинштейн (15 вопросов)",
    icon: <Smile size={20} />,
    questionCount: 15,
    apiPrefix: "self_esteem",
    resultFields: ["self_esteem_score"],
  },
  {
    id: "mood_scale",
    title: "Шкала настроения",
    description: "Оценка текущего эмоционального состояния (10 вопросов)",
    icon: <Smile size={20} />,
    questionCount: 10,
    apiPrefix: "mood_scale",
    resultFields: ["positive_affect", "negative_affect", "mood_balance"],
  },
];

const TestsPage: React.FC = () => {
  const [selectedTest, setSelectedTest] = useState<TestInfo | null>(null);
  const [questions, setQuestions] = useState<TestQuestion[]>([]);
  const [answers, setAnswers] = useState<number[]>([]);
  const [currentQuestion, setCurrentQuestion] = useState(0);
  const [loading, setLoading] = useState(true);
  const [testInProgress, setTestInProgress] = useState(false);
  const [testCompleted, setTestCompleted] = useState(false);
  const [testResult, setTestResult] = useState<TestResult | null>(null);
  const [error, setError] = useState("");

  useEffect(() => {
    // Initial load - no specific action needed
    setLoading(false);
  }, []);

  // Reset loading state when navigating away from test
  useEffect(() => {
    if (!testInProgress && !testCompleted) {
      setLoading(false);
    }
  }, [testInProgress, testCompleted]);

  const startTest = async (test: TestInfo) => {
    setLoading(true);
    setError("");
    try {
      let loadedQuestions: TestQuestion[] = [];
      let apiCall: any;

      switch (test.id) {
        case "san":
          apiCall = testsAPI.getSanQuestions;
          break;
        case "emotional_intelligence":
          apiCall = testsAPI.getEmotionalIntelligenceQuestions;
          break;
        case "psm25_stress":
          apiCall = testsAPI.getPSM25Questions;
          break;
        case "spielberger_anxiety":
          apiCall = testsAPI.getSpielbergerQuestions;
          break;
        case "boyko_burnout":
          apiCall = testsAPI.getBoykoQuestions;
          break;
        case "maslach_burnout":
          apiCall = testsAPI.getMaslachQuestions;
          break;
        case "self_esteem":
          apiCall = testsAPI.getSelfEsteemQuestions;
          break;
        case "mood_scale":
          apiCall = testsAPI.getMoodScaleQuestions;
          break;
        default:
          throw new Error("Unknown test type");
      }

      loadedQuestions = await apiCall();
      setQuestions(loadedQuestions);
      setAnswers(new Array(loadedQuestions.length).fill(0));
      setSelectedTest(test);
      setTestInProgress(true);
      setCurrentQuestion(0);
      setTestCompleted(false);
      setTestResult(null);
    } catch (err) {
      console.error("Error loading test:", err);
      setError("Ошибка загрузки теста");
    } finally {
      setLoading(false);
    }
  };

  const handleAnswerSelect = async (answer: number) => {
    const newAnswers = [...answers];
    newAnswers[currentQuestion] = answer;
    setAnswers(newAnswers);

    // Auto-advance for all tests
    if (currentQuestion < questions.length - 1) {
      setTimeout(() => {
        setCurrentQuestion(currentQuestion + 1);
      }, 500);
    } else {
      // If it's the last question, automatically complete the test
      try {
        await completeTest();
      } catch (err) {
        console.error("Error in completeTest:", err);
        // Ensure loading is set to false in case of error
        setLoading(false);
      }
    }
  };

  const completeTest = async () => {
    if (selectedTest === null) {
      setLoading(false);
      return;
    }

    setLoading(true);
    setError("");
    try {
      // Check all answered
      if (answers.some((a) => a === 0)) {
        setError("Пожалуйста, ответьте на все вопросы");
        setLoading(false);
        return;
      }

      let result: TestResult;
      let processCall: any;

      switch (selectedTest.id) {
        case "san":
          processCall = testsAPI.processSanAnswers;
          break;
        case "emotional_intelligence":
          processCall = testsAPI.processEmotionalIntelligenceAnswers;
          break;
        case "psm25_stress":
          processCall = testsAPI.processPSM25Answers;
          break;
        case "spielberger_anxiety":
          processCall = testsAPI.processSpielbergerAnswers;
          break;
        case "boyko_burnout":
          processCall = testsAPI.processBoykoAnswers;
          break;
        case "maslach_burnout":
          processCall = testsAPI.processMaslachAnswers;
          break;
        case "self_esteem":
          processCall = testsAPI.processSelfEsteemAnswers;
          break;
        case "mood_scale":
          processCall = testsAPI.processMoodScaleAnswers;
          break;
        default:
          throw new Error("Unknown test type");
      }

      const response = await processCall(answers);

      // Map response to generic TestResult
      result = {
        wellbeing: response.wellbeing || 5,
        activity: response.activity || 5,
        mood: response.mood || 5,
        interpretation: response.interpretation || "",
        timestamp: response.timestamp || Date.now(),
        // Add specific fields
        ...response,
      };

      setTestResult(result);
      setTestCompleted(true);
      setTestInProgress(false);
    } catch (err) {
      console.error("Error completing test:", err);
      setError("Ошибка при обработке результатов теста");
    } finally {
      setLoading(false);
    }
  };

  const restartTest = () => {
    setTestCompleted(false);
    setTestResult(null);
    setCurrentQuestion(0);
    setAnswers(new Array(questions.length).fill(0));
    setError("");
  };

  const getScoreQuality = (score: number, type?: string) => {
    if (type === "self_esteem") {
      if (score >= 70)
        return { color: "var(--positive-color)", label: "Высокая" };
      if (score > 40)
        return { color: "var(--warning-color)", label: "Средняя" };
      return { color: "var(--negative-color)", label: "Низкая" };
    }
    if (type === "san") {
      if (score <= 3.5) {
        return { color: "var(--negative-color)", label: "Низкий" };
      } else if (score <= 4.5) {
        return { color: "var(--warning-color)", label: "Средний" };
      } else {
        return { color: "var(--positive-color)", label: "Высокий" };
      }
    }
    // Default for 0-10
    if (score >= 7) return { color: "var(--positive-color)", label: "Отлично" };
    if (score >= 5) return { color: "var(--warning-color)", label: "Хорошо" };
    return { color: "var(--negative-color)", label: "Низко" };
  };

  const renderResultDisplay = (result: TestResult) => {
    let scores: ScoreDisplay[] = [
      { key: "wellbeing", label: "Самочувствие", value: result.wellbeing },
      { key: "activity", label: "Активность", value: result.activity },
      { key: "mood", label: "Настроение", value: result.mood },
    ];

    // Add specific scores based on test type
    if (selectedTest?.id === "emotional_intelligence" && result.ei_score) {
      scores.push({
        key: "ei_score",
        label: "Эмоц. интеллект",
        value: result.ei_score,
      });
    } else if (selectedTest?.id === "psm25_stress" && result.total_score) {
      scores.push({
        key: "total_score",
        label: "Уровень стресса",
        value: result.total_score,
        type: "stress",
      });
    } else if (selectedTest?.id === "spielberger_anxiety") {
      scores.push({
        key: "situational_anxiety",
        label: "Ситуативная тревога",
        value: result.situational_anxiety || 0,
      });
      scores.push({
        key: "personal_anxiety",
        label: "Личностная тревога",
        value: result.personal_anxiety || 0,
      });
    } else if (selectedTest?.id === "boyko_burnout") {
      scores.push({
        key: "tension_score",
        label: "Напряжение",
        value: result.tension_score || 0,
      });
      scores.push({
        key: "resistance_score",
        label: "Резистенция",
        value: result.resistance_score || 0,
      });
      scores.push({
        key: "exhaustion_score",
        label: "Истощение",
        value: result.exhaustion_score || 0,
      });
    } else if (selectedTest?.id === "maslach_burnout") {
      scores.push({
        key: "exhaustion_score",
        label: "Истощение",
        value: result.exhaustion_score || 0,
      });
      scores.push({
        key: "depersonalization_score",
        label: "Деперсонализация",
        value: result.depersonalization_score || 0,
      });
      scores.push({
        key: "accomplishment_score",
        label: "Достижения",
        value: result.accomplishment_score || 0,
        reverse: true,
      });
    } else if (selectedTest?.id === "self_esteem" && result.self_esteem_score) {
      scores.push({
        key: "self_esteem_score",
        label: "Самооценка",
        value: result.self_esteem_score,
        type: "self_esteem",
      });
    } else if (selectedTest?.id === "mood_scale") {
      scores.push({
        key: "positive_affect",
        label: "Позитивный аффект",
        value: result.positive_affect || 0,
      });
      scores.push({
        key: "negative_affect",
        label: "Негативный аффект",
        value: result.negative_affect || 0,
      });
      scores.push({
        key: "mood_balance",
        label: "Баланс настроения",
        value: result.mood_balance || 0,
      });
    }

    if (selectedTest?.id === "san") {
      scores = scores.map((score) => ({ ...score, type: "san" }));
    }

    return (
      <div
        style={{
          display: "grid",
          gridTemplateColumns: "repeat(auto-fit, minmax(200px, 1fr))",
          gap: "20px",
          marginBottom: "24px",
        }}
      >
        {scores.map((score) => {
          const quality = getScoreQuality(score.value, score.type);
          const displayValue =
            score.type === "stress" ? score.value : score.value;
          return (
            <div
              key={score.key}
              style={{
                textAlign: "center",
                padding: "20px",
                backgroundColor: "rgba(0, 102, 255, 0.1)",
                borderRadius: "12px",
              }}
            >
              <div
                style={{
                  fontSize: "14px",
                  marginBottom: "8px",
                  fontWeight: "bold",
                }}
              >
                {score.label}
              </div>
              <div
                style={{
                  fontSize: "32px",
                  fontWeight: "bold",
                  color: quality.color,
                  marginBottom: "4px",
                }}
              >
                {displayValue}
              </div>
              <div style={{ fontSize: "12px", color: quality.color }}>
                {quality.label}
              </div>
            </div>
          );
        })}
      </div>
    );
  };

  if (loading) {
    return (
      <div className="container">
        <div className="card text-center">
          <h2>Загрузка...</h2>
        </div>
      </div>
    );
  }

  if (testInProgress && questions.length > 0 && selectedTest) {
    const question = questions[currentQuestion];
    const progress = ((currentQuestion + 1) / questions.length) * 100;
    const showOptions = true; // Always show options for all tests

    return (
      <div className="container">
        <div className="card">
          <div style={{ marginBottom: "16px" }}>
            <div
              style={{
                display: "flex",
                justifyContent: "space-between",
                alignItems: "center",
                marginBottom: "8px",
              }}
            >
              <span style={{ fontSize: "14px", color: "var(--hint-color)" }}>
                {selectedTest.title} - Вопрос {currentQuestion + 1} из{" "}
                {questions.length}
              </span>
              <span style={{ fontSize: "14px", color: "var(--hint-color)" }}>
                {Math.round(progress)}%
              </span>
            </div>
            <div
              style={{
                width: "100%",
                height: "8px",
                backgroundColor: "#e0e0e0",
                borderRadius: "4px",
                overflow: "hidden",
              }}
            >
              <div
                style={{
                  width: `${progress}%`,
                  height: "100%",
                  backgroundColor: "var(--primary-blue)",
                  transition: "width 0.3s ease",
                }}
              />
            </div>
          </div>

          <h3 className="text-center mb-8" style={{ minHeight: "60px" }}>
            {question.question}
          </h3>

          {showOptions ? (
            <div style={{ display: "grid", gap: "12px" }}>
              {question.options.map((option, index) => (
                <button
                  key={index}
                  className={`btn ${
                    answers[currentQuestion] === index + 1 ? "" : "btn-outline"
                  }`}
                  onClick={() => handleAnswerSelect(index + 1)}
                  style={{
                    textAlign: "left",
                    justifyContent: "flex-start",
                    padding: "16px",
                    fontSize: "16px",
                    transition: "all 0.2s ease",
                    borderWidth:
                      answers[currentQuestion] === index + 1 ? "2px" : "1px",
                    borderColor:
                      answers[currentQuestion] === index + 1
                        ? "var(--primary-blue)"
                        : "",
                    backgroundColor:
                      answers[currentQuestion] === index + 1
                        ? "var(--primary-blue)"
                        : "",
                    color:
                      answers[currentQuestion] === index + 1 ? "white" : "",
                    fontWeight:
                      answers[currentQuestion] === index + 1 ? "600" : "400",
                    transform:
                      answers[currentQuestion] === index + 1
                        ? "scale(1.02)"
                        : "scale(1)",
                    boxShadow:
                      answers[currentQuestion] === index + 1
                        ? "0 4px 12px rgba(0, 102, 255, 0.3)"
                        : "none",
                  }}
                >
                  <span
                    style={{
                      marginRight: "12px",
                      fontWeight: "bold",
                      minWidth: "20px",
                      color:
                        answers[currentQuestion] === index + 1
                          ? "white"
                          : "inherit",
                    }}
                  >
                    {index + 1}
                  </span>
                  {option}
                </button>
              ))}
            </div>
          ) : (
            <div
              style={{
                textAlign: "center",
                padding: "40px",
                color: "var(--hint-color)",
              }}
            >
              Загрузка вариантов ответа...
            </div>
          )}
        </div>
      </div>
    );
  }

  if (testCompleted && testResult && selectedTest) {
    return (
      <div className="container">
        <div className="card text-center mb-8">
          <CheckCircle
            size={48}
            style={{ margin: "0 auto 16px", color: "var(--positive-color)" }}
          />
          <h2 className="mb-4">{selectedTest.title} завершен!</h2>
          <p>Спасибо за прохождение теста</p>
        </div>

        <div className="card mb-8">
          <h3
            className="mb-4"
            style={{ display: "flex", alignItems: "center", gap: "8px" }}
          >
            <BarChart3 size={20} />
            Результаты теста {selectedTest.title}
          </h3>

          {renderResultDisplay(testResult)}

          <div
            style={{
              padding: "16px",
              backgroundColor: "var(--card-background)",
              borderRadius: "8px",
            }}
          >
            <h4 style={{ marginBottom: "12px" }}>Интерпретация результатов:</h4>
            <div
              style={{ lineHeight: "1.6", margin: 0, whiteSpace: "pre-line" }}
            >
              {testResult.interpretation}
            </div>
          </div>
        </div>

        <div
          style={{ display: "grid", gridTemplateColumns: "1fr", gap: "12px" }}
        >
          <button className="btn" onClick={restartTest}>
            <TestTube size={16} style={{ marginRight: "8px" }} />
            Пройти еще раз
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="container">
      <div className="card text-center mb-8">
        <h2
          className="mb-4"
          style={{
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            gap: "8px",
          }}
        >
          <Brain size={24} />
          Психологические тесты
        </h2>
        <p>
          Выберите тест для прохождения и отслеживайте динамику вашего состояния
        </p>
      </div>

      {error && (
        <div className="card mb-8 error-message">
          <XCircle
            size={20}
            style={{ marginRight: "8px", verticalAlign: "middle" }}
          />
          {error}
        </div>
      )}

      <div style={{ display: "grid", gap: "20px", marginBottom: "32px" }}>
        {availableTests.map((test) => (
          <div
            key={test.id}
            className="card"
            style={{ cursor: "pointer" }}
            onClick={() => startTest(test)}
          >
            <div style={{ display: "flex", alignItems: "center", gap: "16px" }}>
              <div
                style={{
                  padding: "12px",
                  backgroundColor: "var(--primary-blue)",
                  borderRadius: "8px",
                  color: "white",
                }}
              >
                {test.icon}
              </div>
              <div style={{ flex: 1 }}>
                <h3 style={{ margin: "0 0 4px 0" }}>{test.title}</h3>
                <p
                  style={{
                    margin: 0,
                    color: "var(--hint-color)",
                    fontSize: "14px",
                  }}
                >
                  {test.description}
                </p>
              </div>
              <div style={{ textAlign: "right" }}>
                <div style={{ fontSize: "12px", color: "var(--hint-color)" }}>
                  {test.questionCount} вопросов
                </div>
                <button className="btn btn-small" style={{ marginTop: "4px" }}>
                  Начать тест
                </button>
              </div>
            </div>
          </div>
        ))}
      </div>
  </div>
);
};

export default TestsPage;
