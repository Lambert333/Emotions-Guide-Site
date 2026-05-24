import React, { useState, useEffect } from 'react';
import { Play, Pause, RotateCcw, Heart, Clock } from 'lucide-react';

interface ExerciseState {
  isRunning: boolean;
  timeRemaining: number;
  currentPhase: 'inhale' | 'hold' | 'exhale' | 'rest';
  totalTime: number;
}

const RelaxationPage: React.FC = () => {
  const [breathingExercise, setBreathingExercise] = useState<ExerciseState>({
    isRunning: false,
    timeRemaining: 0,
    currentPhase: 'inhale',
    totalTime: 0
  });

  const [meditationTimer, setMeditationTimer] = useState({
    isRunning: false,
    timeRemaining: 300, // 5 minutes in seconds
    totalTime: 300
  });

  const [selectedTechnique, setSelectedTechnique] = useState<string | null>(null);
  const [isEditingTime, setIsEditingTime] = useState(false);
  const [editedMinutes, setEditedMinutes] = useState('');
  const [editedSeconds, setEditedSeconds] = useState('');

  useEffect(() => {
    let breathingInterval: NodeJS.Timeout;
    if (breathingExercise.isRunning && breathingExercise.timeRemaining > 0) {
      breathingInterval = setInterval(() => {
        setBreathingExercise(prev => {
          if (prev.timeRemaining <= 1) {
            // Move to next phase
            const nextPhase = getNextPhase(prev.currentPhase);
            const nextTime = getPhaseTime(nextPhase);
            return {
              ...prev,
              currentPhase: nextPhase,
              timeRemaining: nextTime,
              totalTime: nextTime
            };
          }
          return { ...prev, timeRemaining: prev.timeRemaining - 1 };
        });
      }, 1000);
    }

    return () => clearInterval(breathingInterval);
  }, [breathingExercise.isRunning]);

  useEffect(() => {
    let meditationInterval: NodeJS.Timeout;
    if (meditationTimer.isRunning) {
      meditationInterval = setInterval(() => {
        setMeditationTimer(prev => {
          if (prev.timeRemaining <= 1) {
            // Stop the timer when it reaches 0
            clearInterval(meditationInterval);
            // Play completion sound
            new Audio('https://assets.mixkit.co/sfx/preview/mixkit-magic-sparkles-3001.mp3').play();
            return { ...prev, isRunning: false, timeRemaining: 0 };
          }
          return { ...prev, timeRemaining: prev.timeRemaining - 1 };
        });
      }, 1000);
    }

    return () => clearInterval(meditationInterval);
  }, [meditationTimer.isRunning]);

  // Отслеживаем изменения состояния meditationTimer для отладки
  useEffect(() => {
    console.log('meditationTimer changed:', meditationTimer);
  }, [meditationTimer]);

  const getPhaseTime = (phase: string) => {
    switch (phase) {
      case 'inhale': return 4;
      case 'hold': return 7;
      case 'exhale': return 8;
      case 'rest': return 4;
      default: return 4;
    }
  };

  const getNextPhase = (currentPhase: string) => {
    switch (currentPhase) {
      case 'inhale': return 'hold';
      case 'hold': return 'exhale';
      case 'exhale': return 'rest';
      case 'rest': return 'inhale';
      default: return 'inhale';
    }
  };

  const getPhaseLabel = (phase: string) => {
    switch (phase) {
      case 'inhale': return 'Вдох';
      case 'hold': return 'Задержка';
      case 'exhale': return 'Выдох';
      case 'rest': return 'Пауза';
      default: return '';
    }
  };

  const getPhaseDescription = (phase: string) => {
    switch (phase) {
      case 'inhale': return 'Медленно вдыхайте через нос';
      case 'hold': return 'Задержите дыхание';
      case 'exhale': return 'Медленно выдыхайте через рот';
      case 'rest': return 'Отдохните перед следующим циклом';
      default: return '';
    }
  };

  const startBreathingExercise = () => {
    setBreathingExercise({
      isRunning: true,
      timeRemaining: 4,
      currentPhase: 'inhale',
      totalTime: 4
    });
  };

  const stopBreathingExercise = () => {
    setBreathingExercise({
      isRunning: false,
      timeRemaining: 0,
      currentPhase: 'inhale',
      totalTime: 0
    });
  };

  const startMeditation = () => {
    setMeditationTimer(prev => ({ ...prev, isRunning: true }));
  };

  const pauseMeditation = () => {
    setMeditationTimer(prev => ({ ...prev, isRunning: false }));
  };

  const resetMeditation = () => {
    setMeditationTimer(prev => {
      // Защита от сброса на стандартное время, если totalTime был изменен
      const resetTime = prev.totalTime > 0 ? prev.totalTime : 300;
      return {
        isRunning: false,
        timeRemaining: resetTime,
        totalTime: resetTime
      };
    });
  };

  const formatTime = (seconds: number) => {
    const mins = Math.floor(seconds / 60);
    const secs = seconds % 60;
    return `${mins.toString().padStart(2, '0')}:${secs.toString().padStart(2, '0')}`;
  };

  const handleTimeEdit = () => {
    const mins = parseInt(editedMinutes) || 0;
    const secs = parseInt(editedSeconds) || 0;
    const totalSeconds = mins * 60 + secs;
    
    // Проверка ограничения: максимум 99 минут 59 секунд (5999 секунд)
    if (totalSeconds > 5999) {
      alert('Максимальное время: 99 минут 59 секунд');
      return;
    }
    
    if (totalSeconds > 0) {
      console.log('Setting meditation timer to:', totalSeconds);
      setMeditationTimer({
        isRunning: false,
        timeRemaining: totalSeconds,
        totalTime: totalSeconds
      });
    }
    setIsEditingTime(false);
    setEditedMinutes('');
    setEditedSeconds('');
  };

  const handleCancelEdit = () => {
    setIsEditingTime(false);
    setEditedMinutes('');
    setEditedSeconds('');
  };

  const handleKeyPress = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter') {
      handleTimeEdit();
    }
  };

  const startEditingTime = () => {
    const mins = Math.floor(meditationTimer.timeRemaining / 60);
    const secs = meditationTimer.timeRemaining % 60;
    setEditedMinutes(mins.toString());
    setEditedSeconds(secs.toString());
    setIsEditingTime(true);
  };

  const BreathingExercise: React.FC = () => (
    <div className="card mb-8">
      <h3 className="mb-4" style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
        <Heart size={20} />
        Дыхательное упражнение "4-7-8"
      </h3>
      
      {breathingExercise.isRunning ? (
        <>
          <div style={{ 
            padding: '24px', 
            backgroundColor: 'rgba(0, 102, 255, 0.1)',
            borderRadius: '12px',
            textAlign: 'center',
            marginBottom: '16px'
          }}>
            <div style={{ fontSize: '48px', fontWeight: 'bold', color: 'var(--primary-blue)', marginBottom: '8px' }}>
              {breathingExercise.timeRemaining}
            </div>
            <div style={{ fontSize: '18px', fontWeight: 'bold', color: 'var(--primary-blue)', marginBottom: '4px' }}>
              {getPhaseLabel(breathingExercise.currentPhase)}
            </div>
            <div style={{ fontSize: '14px', color: 'var(--hint-color)' }}>
              {getPhaseDescription(breathingExercise.currentPhase)}
            </div>
          </div>

          <div style={{ display: 'flex', gap: '8px', justifyContent: 'center' }}>
            <button className="btn" onClick={stopBreathingExercise} style={{ background: 'var(--hint-color)' }}>
              <Pause size={16} style={{ marginRight: '4px' }} />
              Стоп
            </button>
          </div>
        </>
      ) : (
        <>
          <p>Техника "4-7-8" для быстрого расслабления и отдыха:</p>
          <div style={{ 
            padding: '16px', 
            backgroundColor: 'rgba(0, 102, 255, 0.1)',
            borderRadius: '8px',
            margin: '16px 0',
            textAlign: 'center'
          }}>
            <div style={{ fontSize: '24px', fontWeight: 'bold', color: 'var(--primary-blue)' }}>4-7-8</div>
            <p>Вдох - 4 секунды, задержка - 7 секунд, выдох - 8 секунд</p>
          </div>
          
          <div style={{ textAlign: 'center' }}>
            <button className="btn" onClick={startBreathingExercise}>
              <Play size={16} style={{ marginRight: '8px' }} />
              Начать упражнение
            </button>
          </div>
        </>
      )}
    </div>
  );

  const MeditationTimer: React.FC = () => (
    <div className="card mb-8">
      <h3 className="mb-4" style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
        <Clock size={20} />
        Таймер практики
      </h3>

      <div
        style={{
          padding: '24px',
          backgroundColor: 'rgba(76, 175, 80, 0.1)',
          borderRadius: '12px',
          textAlign: 'center',
          marginBottom: '16px',
          cursor: meditationTimer.isRunning ? 'default' : 'pointer'
        }}
        onClick={() => {
          if (!meditationTimer.isRunning && !isEditingTime) {
            startEditingTime();
          } else if (isEditingTime) {
            handleCancelEdit();
          }
        }}
      >
        {isEditingTime ? (
          <div style={{ display: 'flex', gap: '8px', justifyContent: 'center', alignItems: 'center' }}>
            <input
              type="number"
              value={editedMinutes}
              onChange={(e) => setEditedMinutes(e.target.value)}
              onKeyPress={handleKeyPress}
              onClick={(e) => e.stopPropagation()}
              placeholder="Мин"
              min="0"
              max="99"
              style={{
                width: '60px',
                padding: '8px',
                border: '1px solid #e0e0e0',
                borderRadius: '4px',
                fontSize: '16px',
                textAlign: 'center'
              }}
              autoFocus
            />
            <span style={{ fontSize: '24px', fontWeight: 'bold' }}>:</span>
            <input
              type="number"
              value={editedSeconds}
              onChange={(e) => setEditedSeconds(e.target.value)}
              onKeyPress={handleKeyPress}
              onClick={(e) => e.stopPropagation()}
              placeholder="Сек"
              min="0"
              max="59"
              style={{
                width: '60px',
                padding: '8px',
                border: '1px solid #e0e0e0',
                borderRadius: '4px',
                fontSize: '16px',
                textAlign: 'center'
              }}
            />
            <button
              onClick={(e) => {
                e.stopPropagation();
                handleTimeEdit();
              }}
              style={{
                padding: '8px 12px',
                background: 'var(--positive-color)',
                color: 'white',
                border: 'none',
                borderRadius: '4px',
                cursor: 'pointer',
                marginLeft: '8px'
              }}
            >
              OK
            </button>
            <button
              onClick={(e) => {
                e.stopPropagation();
                handleCancelEdit();
              }}
              style={{
                padding: '8px 12px',
                background: 'var(--hint-color)',
                color: 'white',
                border: 'none',
                borderRadius: '4px',
                cursor: 'pointer'
              }}
            >
              Отмена
            </button>
          </div>
        ) : (
          <>
            <div style={{ fontSize: '48px', fontWeight: 'bold', color: 'var(--positive-color)' }}>
              {formatTime(meditationTimer.timeRemaining)}
            </div>
            <div style={{ fontSize: '14px', color: 'var(--hint-color)' }}>
              {meditationTimer.isRunning ? 'Медитация в процессе...' : 'Нажмите для редактирования'}
            </div>
          </>
        )}
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: '8px', marginBottom: '16px' }}>
        <button
          className="btn"
          onClick={() => setMeditationTimer({
            isRunning: false,
            timeRemaining: 300,
            totalTime: 300
          })}
          disabled={meditationTimer.isRunning || isEditingTime}
        >
          5 мин
        </button>
        <button
          className="btn"
          onClick={() => setMeditationTimer({
            isRunning: false,
            timeRemaining: 600,
            totalTime: 600
          })}
          disabled={meditationTimer.isRunning || isEditingTime}
        >
          10 мин
        </button>
        <button
          className="btn"
          onClick={() => setMeditationTimer({
            isRunning: false,
            timeRemaining: 900,
            totalTime: 900
          })}
          disabled={meditationTimer.isRunning || isEditingTime}
        >
          15 мин
        </button>
      </div>


      <div style={{ display: 'flex', gap: '8px', justifyContent: 'center' }}>
        {meditationTimer.isRunning ? (
          <button className="btn" onClick={pauseMeditation}>
            <Pause size={16} style={{ marginRight: '4px' }} />
            Пауза
          </button>
        ) : (
          <button className="btn" onClick={startMeditation} disabled={meditationTimer.timeRemaining === 0}>
            <Play size={16} style={{ marginRight: '4px' }} />
            Старт
          </button>
        )}
        <button className="btn" onClick={resetMeditation} style={{ background: 'var(--hint-color)' }}>
          <RotateCcw size={16} style={{ marginRight: '4px' }} />
          Сброс
        </button>
      </div>
    </div>
  );

  return (
    <div className="container">
      <div className="card text-center mb-8">
        <h2 className="mb-4">Практики расслабления</h2>
        <p>Короткие практики для расслабления и отдыха</p>
      </div>

      <BreathingExercise />
      <MeditationTimer />

      <div className="card mb-8">
        <h3 className="mb-4">Техники расслабления</h3>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(250px, 1fr))', gap: '16px' }}>
          {[
            {
              title: 'Прогрессивная релаксация',
              description: 'Поочередное напряжение и расслабление мышц',
              steps: ['Начните с пальцев ног', 'Напрягайте каждую группу мышц на 5 секунд', 'Медленно расслабляйте', 'Переходите к следующей группе']
            },
            {
              title: 'Визуализация',
              description: 'Представление спокойных и приятных образов',
              steps: ['Закройте глаза', 'Представьте peaceful место', 'Используйте все органы чувств', 'Проведите там 5-10 минут']
            },
            {
              title: 'Глубокое дыхание',
              description: 'Диафрагмальное дыхание для расслабления',
              steps: ['Сядьте удобно', 'Руку на живот', 'Вдыхайте глубоко через нос', 'Выдыхайте медленно через рот']
            },
            {
              title: 'Упражнение «Быстрая релаксация»',
              description: 'Техника для быстрого снятия физического и внутреннего напряжения, помогает восстановить энергию.',
              steps: [
                'Лягте поудобнее, руки вдоль тела, закройте глаза и ничего не предпринимайте. Просто лежите.',
                'Подумайте о чем-нибудь приятном. Можете вспомнить что-либо или вообразить.',
                'Если вам вспомнится или представится что-нибудь неприятное, просто не реагируйте на это.',
                'Вызовите в себе ощущения, которые предшествуют вашему погружению в сон: тяжесть в руках, в ногах, чувство общей расслабленности.',
                'Представьте, как ощущение расслабленности и покоя распространяется на все ваше тело.',
                'Почувствуйте, как с каждым последующим выдохом расслабленность и покой становятся все более ощутимыми.',
                'Если вам действительно будет хорошо, скажите себе, что это именно то, чего вы желали.',
                'Можете просто отдыхать или потешить себя какими-нибудь приятными фантазиями.',
                'Продолжайте лежать до тех пор, пока вам это нравится.',
                'Не торопитесь с окончанием. Тело само подскажет оптимальный темп.',
                'Отследите свое состояние.'
              ]
            },
            {
              title: 'Прогрессивная мышечная релаксация по Джекобсону',
              description: 'Метод осознанного напряжения и расслабления различных групп мышц для снятия физических зажимов.',
              steps: [
                'Займите удобное положение лежа или сидя.',
                'Сделайте 5-6 медленных вдохов и выдохов.',
                'Последовательно напрягайте и расслабляйте различные группы мышц.',
                'Напрягайте каждую группу на 5-7 секунд, затем расслабляйте на 20-30 секунд.',
                'Начните с кистей рук: сожмите кулаки.',
                'Затем предплечья и плечи: согните руки в локтях и напрягите бицепсы.',
                'Плечи: поднимите к ушам.',
                'Верхняя часть спины: сведите лопатки вместе.',
                'Шея: осторожно откиньте голову назад.',
                'Лицо: напрягите лоб, сожмите челюсти, зажмурьте глаза.',
                'Грудь и живот: глубоко вдохните и напрягите мышцы.',
                'Ягодицы: напрягите ягодичные мышцы.',
                'Бедра: напрягите мышцы бедер.',
                'Голени: вытяните носки на себя.',
                'Стопы: подогните пальцы ног.',
                'После завершения оставайтесь в состоянии расслабления 1-2 минуты.'
              ]
            },
            {
              title: 'Визуализация «Безопасное место»',
              description: 'Практика для возвращения к спокойному образу места, вызывающего чувство безопасности и комфорта.',
              steps: [
                'Займите удобное положение, закройте глаза и сделайте несколько глубоких вдохов.',
                'Представьте место, где вы чувствуете себя абсолютно безопасно и комфортно.',
                'Добавьте детали: что вы видите вокруг?',
                'Обратите внимание на звуки: шум волн, пение птиц, тишина...',
                'Ощутите запахи: морской бриз, аромат цветов, запах леса...',
                'Почувствуйте физические ощущения: тепло солнца, прохладный ветерок...',
                'Если присутствуют, обратите внимание на вкусы.',
                'Полностью погрузитесь в этот образ, ощутите безопасность и покой.',
                'Медленно сосчитайте от 5 до 1, возвращаясь в настоящий момент.',
                'Откройте глаза, сохраняя чувство спокойствия.'
              ]
            }
          ].map((technique, index) => (
            <div
              key={index}
              style={{ 
                padding: '16px', 
                backgroundColor: 'var(--card-background)',
                borderRadius: '8px',
                border: selectedTechnique === technique.title ? '2px solid var(--primary-blue)' : '1px solid #e0e0e0',
                cursor: 'pointer',
                transition: 'all 0.2s ease'
              }}
              onClick={() => setSelectedTechnique(selectedTechnique === technique.title ? null : technique.title)}
            >
              <h4 style={{ margin: '0 0 8px 0' }}>{technique.title}</h4>
              <p style={{ margin: '0 0 12px 0', fontSize: '14px', color: 'var(--hint-color)' }}>
                {technique.description}
              </p>
              
              {selectedTechnique === technique.title && (
                <div style={{ padding: '12px', backgroundColor: 'rgba(0, 102, 255, 0.1)', borderRadius: '6px' }}>
                  <strong style={{ display: 'block', marginBottom: '8px' }}>Как выполнять:</strong>
                  <ol style={{ paddingLeft: '20px', margin: 0, fontSize: '13px' }}>
                    {technique.steps.map((step, i) => (
                      <li key={i} style={{ marginBottom: '4px' }}>{step}</li>
                    ))}
                  </ol>
                </div>
              )}
            </div>
          ))}
        </div>
      </div>
      
    </div>
  );
}

export default RelaxationPage;
