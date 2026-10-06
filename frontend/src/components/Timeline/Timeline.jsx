import React from 'react';
import { fmt } from '../../utils/helpers.js';
export default function Timeline({ items }) {
  if (!items?.length) return <div className="empty">No timeline entries.</div>;
  return <div className="timeline">{items.map((t, i) => <div key={i}>• {t.message} {t.at && <span style={{ color: 'var(--muted)' }}>— {fmt(t.at)}</span>} {t.by && <span> by {t.by}</span>}</div>)}</div>;
}
