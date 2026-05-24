import React, { useState, useEffect, useRef } from "react";
import ReactMarkdown from "react-markdown";
import {
  Bot,
  Brain,
  MessageSquare,
  Send,
  RefreshCw,
  Trash2,
  Sparkles,
} from "lucide-react";
import { chatAPI } from "../services/api";

interface ChatMessage {
  messageId: string;
  userId: string;
  content: string;
  isUser: boolean;
  timestamp: string;
}

interface ChatMetadata {
  last_chat_time: number;
  chat_cooldown_remaining: number;
  last_analysis_time: number;
  analysis_cooldown_remaining: number;
}

const normalizeContent = (content: string): string => {
  // Normalize line endings and collapse excessive newlines while preserving intentional breaks
  return content
    .replace(/\r\n/g, "\n") // Normalize CRLF to LF
    .replace(/\n{2,}/g, "\n\n") // Collapse 2+ newlines to double for stricter control
    .replace(/^[\s\n]+|[\s\n]+$/g, "") // Trim leading/trailing whitespace and newlines
    .trim();
};

const AIPsychologistPage: React.FC = () => {
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [inputMessage, setInputMessage] = useState("");
  const [loading, setLoading] = useState(true);
  const [sending, setSending] = useState(false);
  const [aiPending, setAiPending] = useState(false);
  const [currentAiMessage, setCurrentAiMessage] = useState("");
  const [analyzing, setAnalyzing] = useState(false);
  const [metadata, setMetadata] = useState<ChatMetadata | null>(null);
  const [error, setError] = useState("");
  const [analysisCooldownRemaining, setAnalysisCooldownRemaining] = useState(0);
  const chatContainerRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    loadChatData();
  }, []);

  useEffect(() => {
    scrollToBottom();
  }, [messages]);

  // Update cooldown states when metadata changes
  useEffect(() => {
    if (metadata) {
      const analysisRemaining = Math.max(
        0,
        metadata.analysis_cooldown_remaining
      );
      setAnalysisCooldownRemaining(Math.ceil(analysisRemaining / 1000));
    } else {
      setAnalysisCooldownRemaining(0);
    }
  }, [metadata]);

  // Real-time cooldown timer
  useEffect(() => {
    const interval = setInterval(() => {
      setAnalysisCooldownRemaining((prev) => Math.max(0, prev - 1));
    }, 1000);

    return () => clearInterval(interval);
  }, []);

  const loadChatData = async () => {
    try {
      const [messagesData, metadataData] = await Promise.all([
        chatAPI.getMessages(50),
        chatAPI.getMetadata(),
      ]);

      // Ensure messages are sorted by timestamp
      const sortedMessages = [...messagesData].sort(
        (a, b) =>
          new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime()
      );
      setMessages(sortedMessages);
      setMetadata(metadataData);
    } catch (error) {
      console.error("Error loading chat data:", error);
      setError("Ошибка загрузки чата");
    } finally {
      setLoading(false);
    }
  };

  const scrollToBottom = () => {
    if (chatContainerRef.current) {
      chatContainerRef.current.scrollTop =
        chatContainerRef.current.scrollHeight;
    }
  };

  const handleSendMessage = async () => {
    if (!inputMessage.trim() || sending) return;

    setSending(true);
    setError("");
    setAiPending(true);
    setCurrentAiMessage("ИИ-психолог готовит ответ... Пожалуйста, подождите.");

    try {
      // Add user message immediately
      const userMessage: ChatMessage = {
        messageId: Date.now().toString(),
        userId: "current-user",
        content: inputMessage.trim(),
        isUser: true,
        timestamp: new Date().toISOString(),
      };

      setMessages((prev) => [...prev, userMessage]);
      setInputMessage("");

      // Send message via API
      await chatAPI.sendMessage({
        content: inputMessage.trim(),
        isUser: true,
      });

      // Reload to get AI response
      await loadChatData();
    } catch (error) {
      console.error("Error sending message:", error);
      setError("Ошибка отправки сообщения");
    } finally {
      setSending(false);
      setAiPending(false);
      setCurrentAiMessage("");
    }
  };

  const handleAnalyzeEmotions = async () => {
    if (analyzing) return;

    setAnalyzing(true);
    setError("");
    setAiPending(true);
    setCurrentAiMessage(
      "Анализ вашего состояния в процессе... Пожалуйста, подождите."
    );

    try {
      await chatAPI.analyzeEmotions();
      // Reload messages to get analysis results
      await loadChatData();
    } catch (error: any) {
      console.error("Error analyzing emotions:", error);
      if (error.response?.status === 429) {
        setError("Подождите перед следующим анализом");
      } else {
        setError("Ошибка анализа эмоций");
      }
    } finally {
      setAnalyzing(false);
      setAiPending(false);
      setCurrentAiMessage("");
    }
  };

  const handleClearHistory = async () => {
    if (window.confirm("Вы уверены, что хотите очистить историю чата?")) {
      try {
        await chatAPI.clearHistory();
        setMessages([]);
        await loadChatData();
      } catch (error) {
        console.error("Error clearing history:", error);
        setError("Ошибка очистки истории");
      }
    }
  };

  const handleKeyPress = (e: React.KeyboardEvent) => {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      handleSendMessage();
    }
  };

  const formatTime = (timestamp: string) => {
    return new Date(timestamp).toLocaleTimeString("ru-RU", {
      hour: "2-digit",
      minute: "2-digit",
    });
  };

  const canAnalyze = () => {
    return !analyzing && analysisCooldownRemaining <= 0;
  };

  if (loading) {
    return (
      <div className="container">
        <div className="card text-center">
          <h2>Загрузка чата...</h2>
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
          <Bot size={24} />
          ИИ-психолог
        </h2>
        <p>Получите персональные рекомендации на основе ваших данных</p>
      </div>

      {error && <div className="card mb-8 error-message">{error}</div>}

      <div className="card mb-8">
        <div
          style={{
            display: "flex",
            justifyContent: "space-between",
            alignItems: "center",
            marginBottom: "16px",
          }}
        >
          <h3
            style={{
              display: "flex",
              alignItems: "center",
              gap: "8px",
              margin: 0,
            }}
          >
            <Brain size={20} />
            Анализ вашего состояния
          </h3>
          <button
            className="btn"
            onClick={handleAnalyzeEmotions}
            disabled={!canAnalyze()}
            style={{ padding: "8px 12px", fontSize: "12px" }}
          >
            {analyzing ? (
              <RefreshCw
                size={14}
                className="spinner"
                style={{ marginRight: "4px" }}
              />
            ) : (
              <Sparkles size={14} style={{ marginRight: "4px" }} />
            )}
            {analyzing ? "Анализ..." : "Проанализировать"}
          </button>
        </div>

        {analysisCooldownRemaining > 0 && (
          <div
            style={{
              padding: "8px 12px",
              backgroundColor: "rgba(255, 152, 0, 0.1)",
              borderRadius: "4px",
              marginBottom: "12px",
              fontSize: "12px",
              color: "var(--warning-color)",
            }}
          >
            ⏳ Следующий анализ через: {analysisCooldownRemaining} сек.
          </div>
        )}

        <p>
          На основе последних результатов тестов САН будет проведен глубокий
          анализ вашего эмоционального состояния с использованием искусственного
          интеллекта.
        </p>

        <div
          style={{
            padding: "12px",
            backgroundColor: "var(--card-background)",
            borderRadius: "8px",
            marginTop: "12px",
            fontSize: "14px",
          }}
        >
          <strong>Что анализирует ИИ:</strong>
          <ul style={{ paddingLeft: "30px", margin: "8px 0 0 0" }}>
            <li>Динамика вашего состояния с течением времени</li>
            <li>Взаимосвязь между самочувствием, активностью и настроением</li>
            <li>Паттерны и тренды эмоционального состояния</li>
            <li>Персональные рекомендации для улучшения</li>
          </ul>
        </div>
      </div>

      <div className="card mb-8">
        <div
          style={{
            display: "flex",
            justifyContent: "space-between",
            alignItems: "center",
            marginBottom: "16px",
          }}
        >
          <h3
            style={{
              display: "flex",
              alignItems: "center",
              gap: "8px",
              margin: 0,
            }}
          >
            <MessageSquare size={20} />
            Чат с ИИ-психологом
          </h3>
          <button
            className="btn"
            onClick={handleClearHistory}
            style={{
              padding: "8px 12px",
              fontSize: "12px",
              background: "var(--hint-color)",
            }}
          >
            <Trash2 size={14} style={{ marginRight: "4px" }} />
            Очистить
          </button>
        </div>

        <div
          ref={chatContainerRef}
          style={{
            height: "500px",
            border: "1px solid #e0e0e0",
            borderRadius: "8px",
            padding: "16px",
            marginBottom: "16px",
            overflowY: "auto",
            display: "flex",
            flexDirection: "column",
            gap: "12px",
          }}
        >
          {messages.length === 0 ? (
            <div
              style={{
                textAlign: "center",
                color: "var(--hint-color)",
                display: "flex",
                flexDirection: "column",
                justifyContent: "center",
                alignItems: "center",
                height: "100%",
                gap: "8px",
              }}
            >
              <Bot size={32} />
              <div>
                Здравствуйте! Я ваш ИИ-психолог. Расскажите, как у вас дела?
              </div>
            </div>
          ) : (
            messages.map((message, index) => (
              <div
                key={message.messageId || message.timestamp || index}
                style={{
                  display: "flex",
                  justifyContent: message.isUser ? "flex-end" : "flex-start",
                  marginBottom: "8px",
                }}
              >
                <div
                  style={{
                    maxWidth: message.isUser ? "60%" : "100%",
                    padding: message.isUser
                      ? "12px 16px"
                      : "12px 16px 12px 32px",
                    borderRadius: "18px",
                    backgroundColor: message.isUser
                      ? "var(--primary-blue)"
                      : "var(--card-background)",
                    color: message.isUser ? "white" : "var(--text-color)",
                    border: message.isUser ? "none" : "1px solid #e0e0e0",
                    position: "relative",
                    wordBreak: "break-word",
                    overflowWrap: "break-word",
                    whiteSpace: "pre-wrap",
                    hyphens: "auto",
                  }}
                >
                  <div style={{ marginBottom: "4px" }}>
                    <ReactMarkdown
                      components={{
                        p: ({ children }) => (
                          <p style={{ margin: "0 0 0.5em 0", lineHeight: 1.6 }}>
                            {children}
                          </p>
                        ),
                        br: ({ children }) => (
                          <>{children}</> // Remove extra spacing from breaks
                        ),
                        ol: ({ children, ...props }) => (
                          <ol
                            style={{ paddingLeft: "2em", margin: "0.25em 0" }}
                            {...props}
                          >
                            {children}
                          </ol>
                        ),
                        ul: ({ children, ...props }) => (
                          <ul
                            style={{ paddingLeft: "2em", margin: "0.25em 0" }}
                            {...props}
                          >
                            {children}
                          </ul>
                        ),
                        li: ({ children }) => (
                          <li style={{ marginBottom: "0.125em" }}>
                            {children}
                          </li>
                        ),
                      }}
                    >
                      {normalizeContent(message.content)}
                    </ReactMarkdown>
                  </div>
                  <div
                    style={{
                      fontSize: "10px",
                      opacity: 0.7,
                      textAlign: "right",
                    }}
                  >
                    {formatTime(message.timestamp)}
                  </div>
                </div>
              </div>
            ))
          )}
          {aiPending && (
            <div
              key="ai-pending"
              style={{
                display: "flex",
                justifyContent: "flex-start",
                marginBottom: "8px",
              }}
            >
              <div
                style={{
                  maxWidth: "100%",
                  padding: "12px 16px 12px 32px",
                  borderRadius: "18px",
                  backgroundColor: "var(--card-background)",
                  color: "var(--text-color)",
                  border: "1px solid #e0e0e0",
                  position: "relative",
                  wordBreak: "break-word",
                  overflowWrap: "break-word",
                  whiteSpace: "pre-wrap",
                  hyphens: "auto",
                }}
              >
                <ReactMarkdown
                  components={{
                    p: ({ children }) => (
                      <p style={{ margin: "0 0 0.5em 0", lineHeight: 1.6 }}>
                        {children}
                      </p>
                    ),
                    br: ({ children }) => (
                      <>{children}</> // Remove extra spacing from breaks
                    ),
                    ol: ({ children, ...props }) => (
                      <ol
                        style={{ paddingLeft: "2em", margin: "0.25em 0" }}
                        {...props}
                      >
                        {children}
                      </ol>
                    ),
                    ul: ({ children, ...props }) => (
                      <ul
                        style={{ paddingLeft: "2em", margin: "0.25em 0" }}
                        {...props}
                      >
                        {children}
                      </ul>
                    ),
                    li: ({ children }) => (
                      <li style={{ marginBottom: "0.125em" }}>{children}</li>
                    ),
                  }}
                >
                  {normalizeContent(
                    currentAiMessage || "ИИ анализирует ваше состояние..."
                  )}
                </ReactMarkdown>
                {currentAiMessage === "" && (
                  <div
                    style={{
                      display: "flex",
                      alignItems: "center",
                      gap: "8px",
                      marginTop: "8px",
                    }}
                  >
                    <div
                      className="spinner"
                      style={{
                        width: "16px",
                        height: "16px",
                        borderWidth: "2px",
                      }}
                    ></div>
                    <span style={{ fontSize: "12px", opacity: 0.7 }}>
                      Анализ в процессе... Это может занять несколько секунд
                    </span>
                  </div>
                )}
              </div>
            </div>
          )}
        </div>

        <div style={{ display: "flex", gap: "8px" }}>
          <input
            type="text"
            placeholder="Введите ваше сообщение..."
            value={inputMessage}
            onChange={(e) => setInputMessage(e.target.value)}
            onKeyPress={handleKeyPress}
            disabled={sending}
            style={{
              flex: 1,
              padding: "12px",
              border: "1px solid #e0e0e0",
              borderRadius: "24px",
              fontSize: "16px",
              opacity: sending ? 0.6 : 1,
            }}
          />
          <button
            className="btn"
            onClick={handleSendMessage}
            disabled={sending || !inputMessage.trim()}
            style={{
              borderRadius: "24px",
              minWidth: "auto",
              padding: "12px 16px",
            }}
          >
            {sending ? (
              <RefreshCw size={16} className="spinner" />
            ) : (
              <Send size={16} />
            )}
          </button>
        </div>
      </div>

      <div className="card">
        <h3 className="mb-4">Персональные рекомендации</h3>
        <p>
          На основе вашего диалога и результатов тестов ИИ-психолог предоставит:
        </p>
        <div
          style={{
            padding: "16px",
            backgroundColor: "rgba(0, 102, 255, 0.1)",
            borderRadius: "8px",
            margin: "16px 0",
          }}
        >
          <ul style={{ paddingLeft: "30px", margin: 0 }}>
            <li>Конкретные техники для улучшения состояния</li>
            <li>Рекомендации по распорядку дня</li>
            <li>Упражнения для снижения стресса</li>
            <li>Советы по улучшению сна и отдыха</li>
            <li>Методы повышения продуктивности</li>
          </ul>
        </div>
        <p style={{ fontSize: "14px", color: "var(--hint-color)", margin: 0 }}>
          💡 Для получения рекомендаций начните диалог с ИИ-психологом или
          запросите анализ вашего состояния
        </p>
      </div>
    
    </div>
  );
};

export default AIPsychologistPage;
