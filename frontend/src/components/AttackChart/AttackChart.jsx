import React from 'react';
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, PieChart, Pie, Cell, LineChart, Line } from 'recharts';

const COLORS = ['#10b981', '#f43f8e', '#00f59b', '#ff3b9a', '#34d399', '#fb7185'];

export function AttackChart({ data }) {
  if (!data?.length) return <div className="empty">No attack data yet.</div>;
  return (
    <ResponsiveContainer width="100%" height={220}>
      <BarChart data={data}>
        <XAxis dataKey="attack" tick={{ fill: '#8ea3c7', fontSize: 11 }} stroke="#1d2c4e" />
        <YAxis tick={{ fill: '#8ea3c7' }} stroke="#1d2c4e" />
        <Tooltip contentStyle={{ backgroundColor: '#0d172e', borderColor: '#1d2c4e', borderRadius: '8px', color: '#f1f5f9' }} />
        <Bar dataKey="count" fill="#10b981" radius={[4, 4, 0, 0]} />
      </BarChart>
    </ResponsiveContainer>
  );
}

export function TimelineChart({ data }) {
  if (!data?.length) return <div className="empty">No timeline data yet.</div>;
  return (
    <ResponsiveContainer width="100%" height={220}>
      <LineChart data={data}>
        <XAxis dataKey="time" tick={{ fill: '#8ea3c7', fontSize: 10 }} stroke="#1d2c4e" />
        <YAxis tick={{ fill: '#8ea3c7' }} stroke="#1d2c4e" />
        <Tooltip contentStyle={{ backgroundColor: '#0d172e', borderColor: '#1d2c4e', borderRadius: '8px', color: '#f1f5f9' }} />
        <Line type="monotone" dataKey="events" stroke="#f43f8e" strokeWidth={2.5} dot={false} activeDot={{ r: 5, fill: '#00f59b' }} />
      </LineChart>
    </ResponsiveContainer>
  );
}

export function SeverityPie({ data }) {
  const rows = (data || []).map(d => ({ name: d._id, value: d.count }));
  if (!rows.length) return <div className="empty">No severity data.</div>;
  return (
    <ResponsiveContainer width="100%" height={220}>
      <PieChart>
        <Pie data={rows} dataKey="value" nameKey="name" outerRadius={80} label>
          {rows.map((_, i) => <Cell key={i} fill={COLORS[i % COLORS.length]} />)}
        </Pie>
        <Tooltip contentStyle={{ backgroundColor: '#0d172e', borderColor: '#1d2c4e', borderRadius: '8px', color: '#f1f5f9' }} />
      </PieChart>
    </ResponsiveContainer>
  );
}
