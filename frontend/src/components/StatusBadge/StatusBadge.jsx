import React from 'react';
export default function StatusBadge({ value }) {
  return <span className={`badge b-${value}`}>{value}</span>;
}
