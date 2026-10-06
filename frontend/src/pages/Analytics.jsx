import React, { useState, useEffect } from 'react';
import api from '../services/api';
import Sidebar from '../components/Sidebar/Sidebar.jsx';
import Navbar from '../components/Navbar/Navbar.jsx';
import { AttackChart, TimelineChart, SeverityPie } from '../components/AttackChart/AttackChart.jsx';

export default function Analytics() {
  const [tl, setTl] = useState([]); const [at, setAt] = useState([]);
  const [sev, setSev] = useState(null); const [ips, setIps] = useState([]); const [svc, setSvc] = useState([]);
  useEffect(() => {
    api.get('/analytics/timeline?days=7').then(r => setTl(r.data));
    api.get('/analytics/attacks').then(r => setAt(r.data));
    api.get('/analytics/severity').then(r => setSev(r.data));
    api.get('/analytics/top-ips').then(r => setIps(r.data));
    api.get('/analytics/services').then(r => setSvc(r.data));
  }, []);
  return <div className="layout"><Sidebar /><div className="main"><Navbar />
    <div className="content"><h2>Analytics</h2>
      <div className="grid2">
        <div className="card"><b>Events per hour</b><TimelineChart data={tl} /></div>
        <div className="card"><b>Attack types</b><AttackChart data={at} /></div>
        <div className="card"><b>Severity (alerts)</b><SeverityPie data={sev?.alerts} /></div>
        <div className="card"><b>Top source IPs</b><table><tbody>{ips.map(x => <tr key={x.ip}><td>{x.ip}</td><td>{x.events}</td></tr>)}</tbody></table></div>
        <div className="card"><b>Top services</b><table><tbody>{svc.map(x => <tr key={x.service}><td>{x.service}</td><td>{x.count}</td></tr>)}</tbody></table></div>
      </div>
    </div></div></div>;
}
