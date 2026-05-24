import React, { useState, useEffect } from 'react';
import { User, Calendar, Save, Edit3, LogOut } from 'lucide-react';
import { profileAPI, authAPI } from '../services/api';
import { useNavigate } from 'react-router-dom';


const ProfilePage: React.FC = () => {
  const [profile, setProfile] = useState({
    username: '',
    email: '',
    createdAt: '',
    updatedAt: ''
  });
  const [editUsername, setEditUsername] = useState('');
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [isEditing, setIsEditing] = useState(false);
  const [message, setMessage] = useState('');
  const [currentPassword, setCurrentPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [confirmNewPassword, setConfirmNewPassword] = useState('');
  const [isChangingPassword, setIsChangingPassword] = useState(false);
  const [changingPassword, setChangingPassword] = useState(false);
  const navigate = useNavigate();

  useEffect(() => {
    loadProfileData();
  }, []);

  const loadProfileData = async () => {
    try {
      const profileData = await profileAPI.getProfile();
      setProfile(profileData);
      setEditUsername(profileData.username);
    } catch (error) {
      console.error('Error loading profile:', error);
      setMessage('Ошибка загрузки профиля');
    } finally {
      setLoading(false);
    }
  };

  const handleSaveProfile = async () => {
    if (!editUsername.trim()) {
      setMessage('Имя пользователя не может быть пустым');
      return;
    }

    setSaving(true);
    setMessage('');

    try {
      const updatedProfile = await profileAPI.updateProfile({
        username: editUsername
      });
      
      setProfile(updatedProfile);
      setIsEditing(false);
      setMessage('Профиль успешно обновлен');
      
      // Update local storage
      localStorage.setItem('username', updatedProfile.username);
      
      // Reload after a short delay to show success message
      setTimeout(() => {
        setMessage('');
      }, 3000);
    } catch (error) {
      console.error('Error updating profile:', error);
      setMessage('Ошибка при сохранении профиля');
    } finally {
      setSaving(false);
    }
  };

  const handleCancelEdit = () => {
    setEditUsername(profile.username);
    setIsEditing(false);
    setMessage('');
  };

  const handleLogout = async () => {
    try {
      const refreshToken = localStorage.getItem('refreshToken');
      if (refreshToken) {
        await authAPI.logout(refreshToken);
      }
    } catch (error) {
      console.error('Logout error:', error);
    } finally {
      localStorage.removeItem('authToken');
      localStorage.removeItem('refreshToken');
      localStorage.removeItem('userId');
      localStorage.removeItem('username');
      navigate('/auth');
    }
  };

  const formatDate = (dateString: string) => {
    if (!dateString) return 'Не указано';
    const date = new Date(dateString);
    return date.toLocaleDateString('ru-RU', {
      year: 'numeric',
      month: 'long',
      day: 'numeric'
    });
  };

  const handleChangePassword = async () => {
    if (!currentPassword || !newPassword || !confirmNewPassword) {
      setMessage('Все поля обязательны для заполнения');
      return;
    }

    if (newPassword !== confirmNewPassword) {
      setMessage('Новые пароли не совпадают');
      return;
    }

    if (newPassword.length < 6) {
      setMessage('Новый пароль должен содержать минимум 6 символов');
      return;
    }

    setChangingPassword(true);
    setMessage('');

    try {
      await authAPI.changePassword({
        currentPassword,
        newPassword
      });

      setMessage('Пароль успешно изменен');
      setCurrentPassword('');
      setNewPassword('');
      setConfirmNewPassword('');
      setIsChangingPassword(false);

      setTimeout(() => {
        setMessage('');
      }, 3000);
    } catch (error) {
      console.error('Error changing password:', error);
      setMessage('Ошибка при изменении пароля');
    } finally {
      setChangingPassword(false);
    }
  };

  const handleCancelPasswordChange = () => {
    setCurrentPassword('');
    setNewPassword('');
    setConfirmNewPassword('');
    setIsChangingPassword(false);
    setMessage('');
  };

  const getInitials = (name: string) => {
    if (!name) return 'U';
    return name.split(' ').map(word => word[0]).join('').toUpperCase();
  };

  if (loading) {
    return (
      <div className="container">
        <div className="card text-center">
          <h2>Загрузка профиля...</h2>
        </div>
      </div>
    );
  }

  return (
    <div className="container">
      <div className="card text-center mb-8">
        <h2 className="mb-4">Профиль пользователя</h2>
        <div style={{ 
          width: '80px', 
          height: '80px', 
          borderRadius: '50%', 
          backgroundColor: 'var(--primary-blue)',
          margin: '0 auto 16px',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          color: 'var(--white)',
          fontSize: '24px',
          fontWeight: 'bold'
        }}>
          {getInitials(profile.username)}
        </div>
        <h3>{profile.username}</h3>
        <p>{profile.email}</p>
        <div style={{ marginTop: '8px', fontSize: '14px', color: 'var(--hint-color)' }}>
          <Calendar size={14} style={{ marginRight: '4px', verticalAlign: 'middle' }} />
          Участник с {formatDate(profile.createdAt)}
        </div>
      </div>

      {message && (
        <div className={`card mb-8 ${message.includes('Ошибка') ? 'error-message' : 'success-message'}`}>
          {message}
        </div>
      )}

      <div className="card mb-8">
        <h3 className="mb-4" style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <User size={20} />
          Настройки профиля
        </h3>
        <div style={{ marginBottom: '16px' }}>
          <label style={{ display: 'block', marginBottom: '8px', fontWeight: 'bold' }}>
            Имя пользователя
          </label>
          <div style={{ display: 'flex', gap: '8px' }}>
            <input 
              type="text" 
              value={editUsername}
              onChange={(e) => setEditUsername(e.target.value)}
              disabled={!isEditing}
              style={{
                flex: 1,
                padding: '12px',
                border: '1px solid #e0e0e0',
                borderRadius: '8px',
                fontSize: '16px',
                opacity: isEditing ? 1 : 0.7
              }}
            />
            {!isEditing ? (
              <button 
                className="btn"
                onClick={() => setIsEditing(true)}
                style={{ minWidth: 'auto' }}
              >
                <Edit3 size={16} />
              </button>
            ) : (
              <>
                <button 
                  className="btn"
                  onClick={handleSaveProfile}
                  disabled={saving}
                  style={{ minWidth: 'auto', background: 'var(--positive-color)' }}
                >
                  <Save size={16} />
                </button>
                <button 
                  className="btn"
                  onClick={handleCancelEdit}
                  style={{ minWidth: 'auto', background: 'var(--hint-color)' }}
                >
                  Отмена
                </button>
              </>
            )}
          </div>
        </div>
        
        <div style={{ marginBottom: '16px' }}>
          <label style={{ display: 'block', marginBottom: '8px', fontWeight: 'bold' }}>
            Email
          </label>
          <input 
            type="email" 
            value={profile.email}
            disabled
            style={{
              width: '100%',
              padding: '12px',
              border: '1px solid #e0e0e0',
              borderRadius: '8px',
              fontSize: '16px',
              opacity: 0.7,
              backgroundColor: '#f5f5f5'
            }}
          />
        </div>

        <div style={{ marginBottom: '16px' }}>
          <label style={{ display: 'block', marginBottom: '8px', fontWeight: 'bold' }}>
            Изменить пароль
          </label>
          {!isChangingPassword ? (
            <button
              className="btn"
              onClick={() => setIsChangingPassword(true)}
              style={{ minWidth: 'auto' }}
            >
              <Edit3 size={16} />
            </button>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
              <input
                type="password"
                placeholder="Текущий пароль"
                value={currentPassword}
                onChange={(e) => setCurrentPassword(e.target.value)}
                style={{
                  padding: '12px',
                  border: '1px solid #e0e0e0',
                  borderRadius: '8px',
                  fontSize: '16px'
                }}
              />
              <input
                type="password"
                placeholder="Новый пароль"
                value={newPassword}
                onChange={(e) => setNewPassword(e.target.value)}
                style={{
                  padding: '12px',
                  border: '1px solid #e0e0e0',
                  borderRadius: '8px',
                  fontSize: '16px'
                }}
              />
              <input
                type="password"
                placeholder="Подтвердите новый пароль"
                value={confirmNewPassword}
                onChange={(e) => setConfirmNewPassword(e.target.value)}
                style={{
                  padding: '12px',
                  border: '1px solid #e0e0e0',
                  borderRadius: '8px',
                  fontSize: '16px'
                }}
              />
              <div style={{ display: 'flex', gap: '8px' }}>
                <button
                  className="btn"
                  onClick={handleChangePassword}
                  disabled={changingPassword}
                  style={{ flex: 1, background: 'var(--positive-color)' }}
                >
                  {changingPassword ? 'Сохранение...' : 'Сохранить'}
                </button>
                <button
                  className="btn"
                  onClick={handleCancelPasswordChange}
                  disabled={changingPassword}
                  style={{ flex: 1, background: 'var(--hint-color)' }}
                >
                  Отмена
                </button>
              </div>
            </div>
          )}
        </div>
        
        <div style={{ fontSize: '14px', color: 'var(--hint-color)' }}>
          <div>Создан: {formatDate(profile.createdAt)}</div>
          <div>Обновлен: {formatDate(profile.updatedAt)}</div>
        </div>

        <div style={{ marginTop: '20px', paddingTop: '16px', borderTop: '1px solid #e0e0e0' }}>
          <button
            className="btn"
            style={{ background: 'var(--hint-color)', width: '100%' }}
            onClick={handleLogout}
          >
            <LogOut size={16} style={{ marginRight: '8px' }} />
            Выйти из аккаунта
          </button>
        </div>
      </div>

  </div>
);
};

export default ProfilePage;
