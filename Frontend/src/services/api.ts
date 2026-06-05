import axios, { AxiosError, AxiosHeaders, InternalAxiosRequestConfig } from 'axios';

// Базовый URL для API бекенда
export const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || 'https://emotions-guide.ru/';

// Создаем экземпляр axios с базовыми настройками
const api = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    'Content-Type': 'application/json',
  },
});

// Интерфейсы для типизации
export interface LoginRequest {
  email: string;
  password: string;
}

export interface RegisterRequest {
  email: string;
  password: string;
  username: string;
  termsAccepted: boolean;
}

export interface ChangePasswordRequest {
  currentPassword: string;
  newPassword: string;
}

export interface AuthResponse {
  userId: string;
  email: string;
  username: string;
  accessToken: string;
  refreshToken: string;
}

export interface ErrorResponse {
  detail: string;
}

interface RetryableRequestConfig extends InternalAxiosRequestConfig {
  _retry?: boolean;
}

export interface UserProfile {
  userId: string;
  email: string;
  username: string;
  createdAt: string;
  updatedAt: string;
}

export interface UpdateProfileRequest {
  username?: string;
}

export interface TestResult {
  resultId: string;
  userId: string;
  wellbeingScore: number;
  activityScore: number;
  moodScore: number;
  timestamp: string;
}

export interface SanQuestion {
  id: number;
  question: string;
  reversed: boolean;
}

export interface SanAnswer {
  questionId: number;
  answer: number;
}

export interface SanProcessRequest {
  answers: number[];
}

export interface SanProcessResponse {
  wellbeing: number;
  activity: number;
  mood: number;
  timestamp: number;
  interpretation: string;
}

export interface TestResultRequest {
  wellbeingScore: number;
  activityScore: number;
  moodScore: number;
  timestamp?: string;
}

export interface ChatMessage {
  messageId: string;
  userId: string;
  content: string;
  isUser: boolean;
  timestamp: string;
}

export interface ChatMessageRequest {
  content: string;
  isUser: boolean;
}

export interface ChatMetadata {
  last_chat_time: number;
  chat_cooldown_remaining: number;
  last_analysis_time: number;
  analysis_cooldown_remaining: number;
}

// New interfaces for other tests
export interface TestQuestion {
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

export interface EmotionalIntelligenceProcessRequest {
  answers: number[];
}

export interface EmotionalIntelligenceProcessResponse {
  ei_score: number;
  interpretation: string;
  timestamp: number;
}

export interface PSM25ProcessRequest {
  answers: number[];
}

export interface PSM25ProcessResponse {
  total_score: number;
  interpretation: string;
  timestamp: number;
}

export interface SpielbergerProcessRequest {
  answers: number[];
}

export interface SpielbergerProcessResponse {
  situational_anxiety: number;
  personal_anxiety: number;
  interpretation: string;
  timestamp: number;
}

export interface BoykoProcessRequest {
  answers: number[];
}

export interface BoykoProcessResponse {
  total_score: number;
  tension_score: number;
  resistance_score: number;
  exhaustion_score: number;
  interpretation: string;
  timestamp: number;
}

export interface MaslachProcessRequest {
  answers: number[];
}

export interface MaslachProcessResponse {
  exhaustion_score: number;
  depersonalization_score: number;
  accomplishment_score: number;
  interpretation: string;
  timestamp: number;
}

export interface SelfEsteemProcessRequest {
  answers: number[];
}

export interface SelfEsteemProcessResponse {
  self_esteem_score: number;
  interpretation: string;
  timestamp: number;
}

export interface MoodScaleProcessRequest {
  answers: number[];
}

export interface MoodScaleProcessResponse {
  positive_affect: number;
  negative_affect: number;
  mood_balance: number;
  interpretation: string;
  timestamp: number;
}

// Функция для установки токена авторизации
export const setAuthToken = (token: string | null) => {
  if (token) {
    api.defaults.headers.common['Authorization'] = `Bearer ${token}`;
  } else {
    delete api.defaults.headers.common['Authorization'];
  }
};

const clearAuthAndRedirect = () => {
  localStorage.removeItem('authToken');
  localStorage.removeItem('refreshToken');
  localStorage.removeItem('userId');
  setAuthToken(null);

  if (window.location.pathname !== '/auth') {
    window.location.href = '/auth';
  }
};

// Загрузка токена при инициализации
const token = localStorage.getItem('authToken');
if (token) {
  setAuthToken(token);
}

// API методы
export const authAPI = {
  // Регистрация пользователя
  register: async (data: RegisterRequest): Promise<AuthResponse> => {
    const response = await api.post<AuthResponse>('/api/auth/register', data);
    return response.data;
  },

  // Вход пользователя
  login: async (data: LoginRequest): Promise<AuthResponse> => {
    const response = await api.post<AuthResponse>('/api/auth/login', data);
    return response.data;
  },

  // Обновление токенов
  refresh: async (refreshToken: string): Promise<AuthResponse> => {
    const response = await api.post<AuthResponse>('/api/auth/refresh', {
      refreshToken,
    });
    return response.data;
  },

  // Выход из системы
  logout: async (refreshToken: string): Promise<void> => {
    await api.post('/api/auth/logout', { refreshToken });
  },

  // Изменение пароля
  changePassword: async (data: ChangePasswordRequest): Promise<void> => {
    await api.post('/api/auth/change-password', data);
  },
};

export const profileAPI = {
  // Получение профиля пользователя
  getProfile: async (): Promise<UserProfile> => {
    const response = await api.get<UserProfile>('/api/users/profile');
    return response.data;
  },

  // Обновление профиля
  updateProfile: async (data: UpdateProfileRequest): Promise<UserProfile> => {
    const response = await api.put<UserProfile>('/api/users/profile', data);
    return response.data;
  },
};

export const testsAPI = {
  // Получение вопросов для теста САН
  getSanQuestions: async (): Promise<SanQuestion[]> => {
    const response = await api.get<SanQuestion[]>('/api/san/questions');
    return response.data;
  },

  // Обработка ответов теста САН
  processSanAnswers: async (answers: number[]): Promise<SanProcessResponse> => {
    const response = await api.post<SanProcessResponse>('/api/san/process', { answers });
    return response.data;
  },

  // New test methods
  getEmotionalIntelligenceQuestions: async (): Promise<TestQuestion[]> => {
    const response = await api.get<TestQuestion[]>('/api/emotional_intelligence/questions');
    return response.data;
  },

  processEmotionalIntelligenceAnswers: async (answers: number[]): Promise<EmotionalIntelligenceProcessResponse> => {
    const response = await api.post<EmotionalIntelligenceProcessResponse>('/api/emotional_intelligence/process', { answers });
    return response.data;
  },

  getPSM25Questions: async (): Promise<TestQuestion[]> => {
    const response = await api.get<TestQuestion[]>('/api/psm25_stress/questions');
    return response.data;
  },

  processPSM25Answers: async (answers: number[]): Promise<PSM25ProcessResponse> => {
    const response = await api.post<PSM25ProcessResponse>('/api/psm25_stress/process', { answers });
    return response.data;
  },

  getSpielbergerQuestions: async (): Promise<TestQuestion[]> => {
    const response = await api.get<TestQuestion[]>('/api/spielberger_anxiety/questions');
    return response.data;
  },

  processSpielbergerAnswers: async (answers: number[]): Promise<SpielbergerProcessResponse> => {
    const response = await api.post<SpielbergerProcessResponse>('/api/spielberger_anxiety/process', { answers });
    return response.data;
  },

  getBoykoQuestions: async (): Promise<TestQuestion[]> => {
    const response = await api.get<TestQuestion[]>('/api/boyko_burnout/questions');
    return response.data;
  },

  processBoykoAnswers: async (answers: number[]): Promise<BoykoProcessResponse> => {
    const response = await api.post<BoykoProcessResponse>('/api/boyko_burnout/process', { answers });
    return response.data;
  },

  getMaslachQuestions: async (): Promise<TestQuestion[]> => {
    const response = await api.get<TestQuestion[]>('/api/maslach_burnout/questions');
    return response.data;
  },

  processMaslachAnswers: async (answers: number[]): Promise<MaslachProcessResponse> => {
    const response = await api.post<MaslachProcessResponse>('/api/maslach_burnout/process', { answers });
    return response.data;
  },

  getSelfEsteemQuestions: async (): Promise<TestQuestion[]> => {
    const response = await api.get<TestQuestion[]>('/api/self_esteem/questions');
    return response.data;
  },

  processSelfEsteemAnswers: async (answers: number[]): Promise<SelfEsteemProcessResponse> => {
    const response = await api.post<SelfEsteemProcessResponse>('/api/self_esteem/process', { answers });
    return response.data;
  },

  getMoodScaleQuestions: async (): Promise<TestQuestion[]> => {
    const response = await api.get<TestQuestion[]>('/api/mood_scale/questions');
    return response.data;
  },

  processMoodScaleAnswers: async (answers: number[]): Promise<MoodScaleProcessResponse> => {
    const response = await api.post<MoodScaleProcessResponse>('/api/mood_scale/process', { answers });
    return response.data;
  },

  // Сохранение результата теста
  saveTestResult: async (data: TestResultRequest): Promise<void> => {
    await api.post('/api/test-results', data);
  },

  // Получение результатов тестов
  getTestResults: async (limit: number = 5): Promise<TestResult[]> => {
    const response = await api.get<TestResult[]>(`/api/test-results?limit=${limit}`);
    return response.data;
  },

  // Удаление всех результатов тестов
  deleteTestResults: async (): Promise<void> => {
    await api.delete('/api/test-results');
  },
};

export const chatAPI = {
  // Отправка сообщения в чат
  sendMessage: async (data: ChatMessageRequest): Promise<void> => {
    await api.post('/api/chat/messages', data);
  },

  // Потоковая отправка сообщения в чат
  sendMessageStream: async (data: ChatMessageRequest): Promise<ReadableStream<Uint8Array>> => {
    const response = await fetch(`${API_BASE_URL}/api/chat/messages`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${localStorage.getItem('authToken') || ''}`
      },
      body: JSON.stringify(data)
    });

    if (!response.ok) {
      throw new Error(`HTTP error! status: ${response.status}`);
    }

    return response.body!;
  },

  // Получение истории сообщений
  getMessages: async (limit: number = 20): Promise<ChatMessage[]> => {
    const response = await api.get<ChatMessage[]>(`/api/chat/messages?limit=${limit}`);
    return response.data;
  },

  // Очистка истории чата
  clearHistory: async (): Promise<void> => {
    await api.delete('/api/chat/history');
  },

  // Анализ эмоций по тестам САН
  analyzeEmotions: async (): Promise<void> => {
    await api.post('/api/chat/analyze-emotions');
  },

  // Потоковый анализ эмоций
  analyzeEmotionsStream: async (): Promise<ReadableStream<Uint8Array>> => {
    const response = await fetch(`${API_BASE_URL}/api/chat/analyze-emotions`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${localStorage.getItem('authToken') || ''}`
      }
    });

    if (!response.ok) {
      throw new Error(`HTTP error! status: ${response.status}`);
    }

    return response.body!;
  },

  // Получение метаданных чата
  getMetadata: async (): Promise<ChatMetadata> => {
    const response = await api.get<ChatMetadata>('/api/chat/metadata');
    return response.data;
  },
};

export const analyticsAPI = {
  // Получение статистики тестов (для графиков)
  getTestStatistics: async (limit: number = 30): Promise<TestResult[]> => {
    const response = await api.get<TestResult[]>(`/api/test-results?limit=${limit}`);
    return response.data;
  },
};

// Интерцептор для обработки ошибок авторизации
api.interceptors.response.use(
  (response) => response,
  async (error: AxiosError) => {
    const originalRequest = error.config as RetryableRequestConfig | undefined;
    const isRefreshRequest = originalRequest?.url?.includes('/api/auth/refresh');
    const refreshToken = localStorage.getItem('refreshToken');

    if (
      error.response?.status === 401 &&
      originalRequest &&
      !originalRequest._retry &&
      !isRefreshRequest &&
      refreshToken
    ) {
      originalRequest._retry = true;

      try {
        const authResponse = await authAPI.refresh(refreshToken);

        localStorage.setItem('authToken', authResponse.accessToken);
        localStorage.setItem('refreshToken', authResponse.refreshToken);
        localStorage.setItem('userId', authResponse.userId);
        setAuthToken(authResponse.accessToken);

        const headers = AxiosHeaders.from(originalRequest.headers);
        headers.set('Authorization', `Bearer ${authResponse.accessToken}`);
        originalRequest.headers = headers;

        return api(originalRequest);
      } catch (refreshError) {
        clearAuthAndRedirect();
        return Promise.reject(refreshError);
      }
    }

    if (error.response?.status === 401) {
      clearAuthAndRedirect();
    }

    return Promise.reject(error);
  }
);

export default api;
