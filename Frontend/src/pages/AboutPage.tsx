import React, { useEffect } from 'react';
import {
  ANALYTICS_SOURCE,
  AnalyticsEvents,
} from '../shared/analytics/analyticsEvents';
import { trackEvent } from '../shared/analytics/firebaseAnalytics';

declare global {
  interface Window {
    VK?: {
      Widgets: {
        Post: (containerId: string, ownerId: number, postId: number, hash: string) => void;
      };
    };
  }
}

const AboutPage: React.FC = () => {
  useEffect(() => {
    trackEvent(AnalyticsEvents.FEEDBACK_OPENED, {
      source: ANALYTICS_SOURCE,
      entry_point: 'about',
    });

    // Load Yandex forms script
    const script = document.createElement('script');
    script.src = 'https://forms.yandex.ru/_static/embed.js';
    script.async = true;
    document.body.appendChild(script);

    // Load VK OpenAPI script
    const vkScript = document.createElement('script');
    vkScript.src = 'https://vk.com/js/api/openapi.js?173';
    vkScript.async = true;
    document.head.appendChild(vkScript);

    // Initialize VK widget after script loads
    const initVK = setInterval(() => {
      if (window.VK) {
        window.VK.Widgets.Post("vk_post_-230059842_2", -230059842, 2, 'KNVmhJ6k88QKjFLw6fOMomYtXAuT');
        clearInterval(initVK);
      }
    }, 100);

    return () => {
      document.body.removeChild(script);
      document.head.removeChild(vkScript);
      clearInterval(initVK);
    };
  }, []);

  return (
    <div className="container" style={{ padding: '40px 20px', maxWidth: '800px', margin: '0 auto' }}>
      <h1 style={{ textAlign: 'center', marginBottom: '40px', color: 'var(--text-color)' }}>О нас</h1>
      
      <section style={{ marginBottom: '40px' }}>
        <h2 style={{ marginBottom: '20px', color: 'var(--primary-blue)' }}>Форма обратной связи</h2>
        <p style={{ marginBottom: '20px' }}>Оставьте ваше сообщение, и мы свяжемся с вами в ближайшее время.</p>
        <div className="form-container">
          <iframe
            src="https://forms.yandex.ru/u/67f309bc90fa7b089baaf8dd?iframe=1"
            frameBorder="0"
            name="ya-form-67f309bc90fa7b089baaf8dd"
          />
        </div>
      </section>

      <section style={{ marginBottom: '40px' }}>
        <h2 style={{ marginBottom: '20px', color: 'var(--primary-blue)' }}>Группа ВКонтакте</h2>
        <p style={{ marginBottom: '20px' }}>Присоединяйтесь к нашей группе для обсуждений и новостей.</p>
        <div 
          id="vk_post_-230059842_2" 
          style={{ minHeight: '400px', borderRadius: '8px', overflow: 'hidden' }}
        />
      </section>

      <section>
        <h2 style={{ marginBottom: '20px', color: 'var(--primary-blue)' }}>Электронная почта</h2>
        <p style={{ marginBottom: '20px' }}>Для вопросов и предложений пишите нам на почту:</p>
        <p style={{ 
          fontSize: '18px', 
          fontWeight: 'bold', 
          wordBreak: 'break-all',
          backgroundColor: 'rgba(0, 102, 255, 0.1)',
          padding: '10px',
          borderRadius: '4px',
          borderLeft: '4px solid var(--primary-blue)'
        }}>
          dementjew.vania2016@yandex.ru
        </p>
      </section>
    </div>
  );
};

export default AboutPage;
