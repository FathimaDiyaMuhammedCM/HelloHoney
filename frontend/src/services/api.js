import axios from 'axios';

const rawApiUrl = import.meta.env.VITE_API_URL || '/api';
const baseURL = rawApiUrl.endsWith('/api') ? rawApiUrl : (rawApiUrl === '/' ? '/api' : `${rawApiUrl.replace(/\/+$/, '')}/api`);

const api = axios.create({ baseURL, timeout: 15000 });

api.interceptors.request.use((cfg) => {
  const t = localStorage.getItem('hh_token');
  if (t) cfg.headers.Authorization = `Bearer ${t}`;
  return cfg;
});

export default api;