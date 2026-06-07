import React, { useState } from 'react';
import { toast } from 'react-toastify';
import { authAPI, RegisterRequest, LoginRequest } from '../services/api';
import {
  ANALYTICS_SOURCE,
  AnalyticsEvents,
} from '../shared/analytics/analyticsEvents';
import {
  identifyAnalyticsUser,
  trackEvent,
} from '../shared/analytics/firebaseAnalytics';

const AuthPage: React.FC = () => {
  const [isRegister, setIsRegister] = useState(false);
  const [formData, setFormData] = useState({
    email: '',
    password: '',
    confirmPassword: '',
    username: '',
    termsAccepted: false
  });
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const handleInputChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const { name, value, type, checked } = e.target;
    setFormData(prev => ({
      ...prev,
      [name]: type === 'checkbox' ? checked : value
    }));
  };

  const handleAuthModeToggle = () => {
    const nextIsRegister = !isRegister;
    setIsRegister(nextIsRegister);
    setError('');

    if (nextIsRegister) {
      trackEvent(AnalyticsEvents.SIGN_UP_STARTED, {
        source: ANALYTICS_SOURCE,
        method: 'email',
      });
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError('');

    if (isRegister && formData.password !== formData.confirmPassword) {
      setError('Пароли не совпадают');
      setLoading(false);
      return;
    }

    if (isRegister && formData.password.length < 6) {
      setError('Пароль должен содержать минимум 6 символов');
      setLoading(false);
      return;
    }

    try {
      if (isRegister) {
        const registerData: RegisterRequest = {
          email: formData.email,
          password: formData.password,
          username: formData.username,
          termsAccepted: formData.termsAccepted
        };
        
        const response = await authAPI.register(registerData);
        // Сохраняем токены
        localStorage.setItem('authToken', response.accessToken);
        localStorage.setItem('refreshToken', response.refreshToken);
        localStorage.setItem('userId', response.userId);
        identifyAnalyticsUser(response.userId);
        trackEvent(AnalyticsEvents.SIGN_UP_COMPLETED, {
          source: ANALYTICS_SOURCE,
          method: 'email',
        });

        toast.success('Регистрация успешна!');
        window.location.href = '/';
      } else {
        const loginData: LoginRequest = {
          email: formData.email,
          password: formData.password
        };
        
        const response = await authAPI.login(loginData);
        // Сохраняем токены
        localStorage.setItem('authToken', response.accessToken);
        localStorage.setItem('refreshToken', response.refreshToken);
        localStorage.setItem('userId', response.userId);
        identifyAnalyticsUser(response.userId);
        trackEvent(AnalyticsEvents.LOGIN_COMPLETED, {
          source: ANALYTICS_SOURCE,
          method: 'email',
        });

        toast.success('Вход выполнен успешно!');
        window.location.href = '/';
      }
    } catch (err: any) {
      setError(err.response?.data?.detail || 'Произошла ошибка');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="container">
      <div className="card text-center">
        <h2 className="mb-4">{isRegister ? 'Регистрация' : 'Авторизация'}</h2>
        <p className="mb-8">
          {isRegister ? 'Создайте новый аккаунт' : 'Войдите в свой аккаунт'}
        </p>

        {error && (
          <div className="error-message mb-4" style={{ color: 'red' }}>
            {error}
          </div>
        )}

        <form onSubmit={handleSubmit}>
          {isRegister && (
            <div style={{ marginBottom: '16px' }}>
              <input
                name="username"
                type="text"
                placeholder="Имя пользователя"
                value={formData.username}
                onChange={handleInputChange}
                required={isRegister}
                style={{
                  width: '100%',
                  padding: '12px',
                  border: '1px solid #e0e0e0',
                  borderRadius: '8px',
                  fontSize: '16px'
                }}
              />
            </div>
          )}
          
          <div style={{ marginBottom: '16px' }}>
            <input
              name="email"
              type="email"
              placeholder="Email"
              value={formData.email}
              onChange={handleInputChange}
              required
              style={{
                width: '100%',
                padding: '12px',
                border: '1px solid #e0e0e0',
                borderRadius: '8px',
                fontSize: '16px'
              }}
            />
          </div>
          
          <div style={{ marginBottom: '16px' }}>
            <input
              name="password"
              type="password"
              placeholder="Пароль"
              value={formData.password}
              onChange={handleInputChange}
              required
              style={{
                width: '100%',
                padding: '12px',
                border: '1px solid #e0e0e0',
                borderRadius: '8px',
                fontSize: '16px'
              }}
            />
          </div>

          {isRegister && (
            <div style={{ marginBottom: '16px' }}>
              <input
                name="confirmPassword"
                type="password"
                placeholder="Подтвердите пароль"
                value={formData.confirmPassword}
                onChange={handleInputChange}
                required
                style={{
                  width: '100%',
                  padding: '12px',
                  border: '1px solid #e0e0e0',
                  borderRadius: '8px',
                  fontSize: '16px'
                }}
              />
            </div>
          )}

          {isRegister && (
            <div style={{ marginBottom: '16px', textAlign: 'left' }}>
              <label style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <input
                  name="termsAccepted"
                  type="checkbox"
                  checked={formData.termsAccepted}
                  onChange={handleInputChange}
                  required
                />
                <span>Я принимаю <a href="https://lambert333.github.io/Emotions-Guide-Privacy/" target="_blank" rel="noopener noreferrer" style={{color: 'var(--primary-color)', textDecoration: 'underline'}}>условия использования</a></span>
              </label>
            </div>
          )}
          
          <button
            type="submit"
            className="btn mb-4"
            disabled={loading}
            style={{ width: '100%' }}
          >
            {loading ? 'Загрузка...' : (isRegister ? 'Зарегистрироваться' : 'Войти')}
          </button>
        </form>

        <button
          className="btn"
          style={{ background: 'var(--hint-color)', width: '100%' }}
          onClick={handleAuthModeToggle}
          disabled={loading}
        >
          {isRegister ? 'Уже есть аккаунт? Войти' : 'Нет аккаунта? Зарегистрироваться'}
        </button>
      </div>
    </div>
  );
};

export default AuthPage;
