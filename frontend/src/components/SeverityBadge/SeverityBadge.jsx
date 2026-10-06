import React from 'react';
export default function SeverityBadge({ value }) {
  return <span className={`badge b-${value}`}>{value}</span>;
}
