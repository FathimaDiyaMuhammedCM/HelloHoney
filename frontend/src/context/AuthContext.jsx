import React, { createContext, useContext, useState, useEffect } from 'react';
import api from '../services/api';

const AuthCtx = createContext(null);
export const useAuth = () => useContext(AuthCtx);

export function AuthProvider({ children }) {
  const [user, setUser] = useState(() => {
    try {
      const stored = JSON.parse(localStorage.getItem('hh_user') || 'null');
      // Validate stored token hasn't expired
      const token = localStorage.getItem('hh_token');
      if (token) {
        const payload = JSON.parse(atob(token.split('.')[1]));
        if (payload.exp && payload.exp * 1000 < Date.now()) {
          localStorage.removeItem('hh_token');
          localStorage.removeItem('hh_user');
          return null;
        }
      }
      return stored;
    } catch { return null; }
  });
  const login = async (email, password) => {
    const { data } = await api.post('/auth/login', { email, password });
    localStorage.setItem('hh_token', data.token);
    localStorage.setItem('hh_user', JSON.stringify(data.user));
    setUser(data.user);
    return data.user;
  };
  const logout = () => {
    localStorage.removeItem('hh_token');
    localStorage.removeItem('hh_user');
    setUser(null);
  };
  return <AuthCtx.Provider value={{ user, login, logout }}>{children}</AuthCtx.Provider>;
}
