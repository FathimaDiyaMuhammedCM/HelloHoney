import { useEffect } from 'react';
export function usePolling(fn, ms = 4000, enabled = true) {
  useEffect(() => {
    if (!enabled) return;
    fn();
    const t = setInterval(fn, ms);
    return () => clearInterval(t);
  }, [ms, enabled]);
}
