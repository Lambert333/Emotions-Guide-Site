import React from 'react';
import { Link, useLocation } from 'react-router-dom';
import { Home, User, BarChart3, TestTube, Bot, Heart, Info } from 'lucide-react';

interface NavigationProps {
  collapsed: boolean;
  isMobileOpen: boolean;
  onNavigate: () => void;
}

const Navigation: React.FC<NavigationProps> = ({ collapsed, isMobileOpen, onNavigate }) => {
  const location = useLocation();

  const navItems = [
    { path: '/', icon: Home, label: 'Главная' },
    { path: '/tests', icon: TestTube, label: 'Тесты' },
    { path: '/charts', icon: BarChart3, label: 'Графики' },
    { path: '/ai-psychologist', icon: Bot, label: 'ИИ-Помощник' },
    { path: '/relaxation', icon: Heart, label: 'Релаксация' },
    { path: '/profile', icon: User, label: 'Профиль' },
    { path: '/about', icon: Info, label: 'О нас' },
  ];

  // Width is now handled by CSS classes

  return (
    <nav className={`navigation-sidebar ${collapsed ? 'navigation-collapsed' : ''} ${isMobileOpen ? 'mobile-open' : 'mobile-closed'}`} style={{
      position: 'fixed',
      top: 0,
      left: 0,
      height: '100vh',
      backgroundColor: 'var(--white)',
      borderRight: '1px solid #e0e0e0',
      padding: '20px 0',
      zIndex: 1000,
      overflowY: 'auto',
      transition: 'transform 0.3s ease, width 0.3s ease'
    }}>
      <div className={`nav-container ${collapsed ? 'nav-container-collapsed' : ''}`}>
        <div style={{
          display: 'flex',
          flexDirection: 'column',
          gap: '16px'
        }}>
          {navItems.map((item) => {
            const Icon = item.icon;
            const isActive = location.pathname === item.path;
            
            return (
              <Link
                key={item.path}
                to={item.path}
                className={`nav-link-item ${collapsed ? 'nav-link-item-collapsed' : ''} ${isActive ? 'active' : ''}`}
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: collapsed ? 'center' : 'flex-start',
                  gap: collapsed ? 0 : '12px',
                  textDecoration: 'none',
                  color: isActive ? 'var(--primary-blue)' : 'var(--text-color)',
                  fontWeight: isActive ? '600' : '400',
                  borderRadius: '8px',
                  transition: 'all 0.3s ease',
                  backgroundColor: isActive ? 'rgba(0, 102, 255, 0.1)' : 'transparent',
                  width: '100%',
                  overflow: 'hidden'
                }}
                onClick={onNavigate}
              >
                <Icon size={20} />
                {!collapsed && <span style={{ whiteSpace: 'nowrap' }}>{item.label}</span>}
              </Link>
            );
          })}
        </div>
      </div>
    </nav>
  );
};

export default Navigation;
