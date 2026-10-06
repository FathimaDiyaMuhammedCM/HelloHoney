import { useEffect, useRef } from 'react';
import { io } from 'socket.io-client';

// Subscribes to live backend events (new_event, new_alert, incident_update).
// Calls onUpdate(kind, payload) and returns connection state via onStatus.
export function useRealtime(onUpdate, enabled = true) {
  const fnRef = useRef(onUpdate);
  fnRef.current = onUpdate;

  useEffect(() => {
    if (!enabled) return;
    const socketUrl =
      import.meta.env.VITE_SOCKET_URL ||
      (import.meta.env.VITE_API_URL ? import.meta.env.VITE_API_URL.replace(/\/api\/?$/, '') : '') ||
      (typeof window !== 'undefined' && window.location.port === '5173' ? 'http://localhost:5000' : '/');
    const socket = io(socketUrl, { transports: ['websocket', 'polling'] });
    socket.on('new_event', (d) => fnRef.current && fnRef.current('event', d));
    socket.on('new_alert', (d) => fnRef.current && fnRef.current('alert', d));
    socket.on('incident_update', (d) => fnRef.current && fnRef.current('incident', d));
    return () => socket.disconnect();
  }, [enabled]);
}
