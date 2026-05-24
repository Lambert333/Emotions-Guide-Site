import React, { useState, useEffect } from 'react';
import { Brain, BarChart3, Bot, Heart } from 'lucide-react';
import { profileAPI, testsAPI, type TestResult } from '../services/api';
import { useNavigate } from 'react-router-dom';

interface HomeStats {
  totalTests: number;
  lastTestDate?: string;
  averageWellbeing: number;
  averageActivity: number;
  averageMood: number;
}

const HomePage: React.FC = () => {
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [, setUsername] = useState('');
  const [stats, setStats] = useState<HomeStats>({
    totalTests: 0,
    averageWellbeing: 0,
    averageActivity: 0,
    averageMood: 0
  });
  const [loading, setLoading] = useState(true);
  const navigate = useNavigate();

  useEffect(() => {
    checkAuthentication();
    loadStats();
  }, []);

  const checkAuthentication = () => {
    const token = localStorage.getItem('authToken');
    const storedUsername = localStorage.getItem('username');
    setIsAuthenticated(!!token);
    if (storedUsername) {
      setUsername(storedUsername);
    }
  };

  const loadStats = async () => {
    try {
      const token = localStorage.getItem('authToken');
      if (!token) {
        setLoading(false);
        return;
      }

      const [testResults, userProfile] = await Promise.allSettled([
        testsAPI.getTestResults(30),
        profileAPI.getProfile()
      ]);

      if (testResults.status === 'fulfilled' && testResults.value.length > 0) {
        const tests = testResults.value;
        const total = tests.length;
        const wellbeingSum = tests.reduce((sum: number, test: TestResult) => sum + test.wellbeingScore, 0);
        const activitySum = tests.reduce((sum: number, test: TestResult) => sum + test.activityScore, 0);
        const moodSum = tests.reduce((sum: number, test: TestResult) => sum + test.moodScore, 0);
        const lastTest = tests[0];

        setStats({
          totalTests: total,
          lastTestDate: lastTest.timestamp,
          averageWellbeing: Math.round((wellbeingSum / total) * 10) / 10,
          averageActivity: Math.round((activitySum / total) * 10) / 10,
          averageMood: Math.round((moodSum / total) * 10) / 10
        });
      }

      if (userProfile.status === 'fulfilled') {
        setUsername(userProfile.value.username);
        localStorage.setItem('username', userProfile.value.username);
      }
    } catch (error) {
      console.error('Error loading stats:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleStartTest = () => {
    navigate('/tests');
  };

  const handleNavigateTo = (path: string) => {
    navigate(path);
  };


  const handleLogin = () => {
    navigate('/auth');
  };

  const FeatureCard: React.FC<{
    icon: React.ReactNode;
    title: string;
    description: string;
    onClick: () => void;
    disabled?: boolean;
  }> = ({ icon, title, description, onClick, disabled = false }) => (
    <div className={`card text-center ${disabled ? 'opacity-60' : 'cursor-pointer hover:shadow-lg transition-shadow'}`} onClick={!disabled ? onClick : undefined}>
      <div style={{ margin: '0 auto 16px', color: 'var(--primary-blue)' }}>{icon}</div>
      <h3>{title}</h3>
      <p>{description}</p>
    </div>
  );

  if (loading) {
    return (
      <div className="container">
        <div className="card text-center">
          <h2>Загрузка...</h2>
        </div>
      </div>
    );
  }

  return (
    <div className="container">
      {/* Hero Section */}
      <section className="hero" style={{
        display: 'grid',
        gridTemplateColumns: '1fr 1fr',
        gap: '40px',
        alignItems: 'center',
        marginBottom: '40px',
        padding: '40px 0'
      }}>
        <div>
          <h1 style={{ fontSize: '48px', marginBottom: '20px', color: 'var(--text-color)' }}>
            Эмоции Гид - Твой менеджер эмоций
          </h1>
          <p style={{ fontSize: '18px', marginBottom: '30px', color: 'var(--text-color)', lineHeight: 1.6 }}>
            Отслеживай свое эмоциональное состояние и улучшай ментальное здоровье с помощью персонализированных инструментов
          </p>
          {isAuthenticated ? (
            <button className="btn" onClick={handleStartTest} style={{ fontSize: '18px', padding: '16px 32px' }}>
              Пройти тест САН
            </button>
          ) : (
            <button className="btn" onClick={handleLogin} style={{ fontSize: '18px', padding: '16px 32px' }}>
              Войти в аккаунт
            </button>
          )}
        </div>
        <div style={{ textAlign: 'center' }}>
          <img
            src="/photo 1.svg"
            alt="Эмоции Путь"
            style={{
              maxWidth: '100%',
              height: 'auto',
              maxHeight: '400px'
            }}
          />
        </div>
      </section>

      {isAuthenticated && stats.totalTests > 0 && (
        <div className="card mb-8">
          <h2 className="text-center mb-4">Ваша статистика</h2>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '20px' }}>
            <div style={{ textAlign: 'center' }}>
              <div style={{ fontSize: '24px', fontWeight: 'bold', color: 'var(--primary-blue)' }}>
                {stats.totalTests}
              </div>
              <div>Пройдено тестов</div>
            </div>
            <div style={{ textAlign: 'center' }}>
              <div style={{ fontSize: '24px', fontWeight: 'bold', color: 'var(--positive-color)' }}>
                {stats.averageWellbeing}
              </div>
              <div>Среднее самочувствие</div>
            </div>
            <div style={{ textAlign: 'center' }}>
              <div style={{ fontSize: '24px', fontWeight: 'bold', color: 'var(--primary-blue)' }}>
                {stats.averageActivity}
              </div>
              <div>Средняя активность</div>
            </div>
            <div style={{ textAlign: 'center' }}>
              <div style={{ fontSize: '24px', fontWeight: 'bold', color: 'var(--positive-color)' }}>
                {stats.averageMood}
              </div>
              <div>Среднее настроение</div>
            </div>
          </div>
        </div>
      )}

      <div className="grid" style={{ 
        display: 'grid', 
        gridTemplateColumns: 'repeat(auto-fit, minmax(250px, 1fr))', 
        gap: '20px',
        marginBottom: '40px'
      }}>
        <FeatureCard
          icon={<Brain size={48} />}
          title="Тест САН"
          description="Оцените свое самочувствие, активность и настроение"
          onClick={() => handleNavigateTo('/tests')}
          disabled={!isAuthenticated}
        />

        <FeatureCard
          icon={<BarChart3 size={48} />}
          title="Графики"
          description="Отслеживайте динамику вашего состояния"
          onClick={() => handleNavigateTo('/charts')}
          disabled={!isAuthenticated}
        />

        <FeatureCard
          icon={<Bot size={48} />}
          title="ИИ-психолог"
          description="Получите персональные рекомендации"
          onClick={() => handleNavigateTo('/ai-psychologist')}
          disabled={!isAuthenticated}
        />

        <FeatureCard
          icon={<Heart size={48} />}
          title="Релаксация"
          description="Техники для расслабления и снятия стресса"
          onClick={() => handleNavigateTo('/relaxation')}
        />

      </div>

      {!isAuthenticated && (
        <div className="card" style={{ marginBottom: '40px' }}>
          <div style={{ padding: '16px', backgroundColor: 'rgba(0, 102, 255, 0.1)', borderRadius: '8px' }}>
            <p style={{ margin: 0, fontWeight: 'bold', textAlign: 'center' }}>
              💡 Для доступа ко всем функциям требуется авторизация
            </p>
          </div>
        </div>
      )}

      <div className="card">
        <h2 className="text-center mb-4">О приложении</h2>
        <p>
          Эмоции Гид - это современное веб-приложение, разработанное для помощи пользователям
          в отслеживании и управлении своими эмоциями. Приложение предоставляет инструменты
          для анализа эмоционального состояния, ведения дневника настроения и получения
          персонализированных рекомендаций.
        </p>
      </div>


    </div>
  );
};

export default HomePage;
