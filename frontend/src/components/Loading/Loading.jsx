import React from 'react';
export const Loading = () => <div className="loading">Loading…</div>;
export const EmptyState = ({ text }) => <div className="empty">{text || 'Nothing here yet.'}</div>;
export function Modal({ children, onClose }) {
  return <div className="modal-bg" onClick={onClose}><div className="modal" onClick={e => e.stopPropagation()}>{children}</div></div>;
}
