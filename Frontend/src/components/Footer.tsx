import React from 'react';
import { Link } from 'react-router-dom';

const Footer: React.FC = () => {
  return (
    <footer className="footer" style={{
      backgroundColor: 'var(--white)',
      borderTop: '1px solid #e0e0e0',
      padding: '20px 0',
      marginTop: 'auto',
      width: '100%'
    }}>
      <div className="container" style={{ textAlign: 'center' }}>
        <p style={{ margin: 0, color: 'var(--text-color)' }}>
          &copy; 2025 Эмоции Гид.{' '}
          <a 
            href="https://lambert333.github.io/Emotions-Guide-Privacy/" 
            target="_blank" 
            rel="noopener noreferrer"
            style={{ color: 'var(--primary-blue)', textDecoration: 'none' }}
          >
            Все права защищены
          </a>{' '}
          |{' '}
          <Link 
            to="/about" 
            style={{ color: 'var(--primary-blue)', textDecoration: 'none' }}
          >
            Контактная информация
          </Link>
        </p>
      </div>
    </footer>
  );
};

export default Footer;