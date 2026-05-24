import { initializeApp } from 'firebase/app';
import { getAuth } from 'firebase/auth';
import { getDatabase } from 'firebase/database';

// Конфигурация Firebase из Android приложения
const firebaseConfig = {
  apiKey: "AIzaSyCw7Lb9WcJo10G3kc3rPxBqB662fbLmjbI",
  authDomain: "emotions-guide-c173c.firebaseapp.com",
  databaseURL: "https://emotions-guide-c173c-default-rtdb.firebaseio.com",
  projectId: "emotions-guide-c173c",
  storageBucket: "emotions-guide-c173c.firebasestorage.app",
  messagingSenderId: "132215609179",
  appId: "1:132215609179:web:18a9da4eb49b2f64042c7e"
};

// Инициализация Firebase
const app = initializeApp(firebaseConfig);

// Инициализация сервисов
export const auth = getAuth(app);
export const database = getDatabase(app);

export default app;
