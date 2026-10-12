import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext.jsx';

export default function Login() {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [err, setErr] = useState('');
  const { login } = useAuth();
  const nav = useNavigate();
  const submit = async (e) => {
    e.preventDefault();
    setErr('');
    try { await login(email, password); nav('/'); }
    catch (err) { setErr('Invalid credentials'); }
  };
  return <div style={{ display: 'flex', height: '100vh', alignItems: 'center', justifyContent: 'center' }}>
    <form onSubmit={submit} className="card" style={{ minWidth: 320 }}>
      <h2>🛡️ HELLOHONEY</h2><p style={{ color: 'var(--accent-pink)', fontSize: 12 }}>LAB / SIMULATION MODE — authorized lab only</p>
      <div><input placeholder="Email" value={email} onChange={e => setEmail(e.target.value)} style={{ width: '100%' }} /></div>
      <div><input type="password" placeholder="Password" value={password} onChange={e => setPassword(e.target.value)} style={{ width: '100%' }} /></div>
      {err && <div style={{ color: 'var(--danger)' }}>{err}</div>}
      <button className="btn" type="submit">Login</button>
    </form></div>;
}
export function NotFound() {
  return <div className="content"><h2>404 — Not found</h2></div>;
}
