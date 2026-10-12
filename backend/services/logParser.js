// Log file parser supporting Syslog, CSV, TSV, JSON, JSON-Lines, Common Web Log, KV/Firewall, PCAP, and Raw Honeypot logs.
"use strict";

const MONTHS = { jan: 0, feb: 1, mar: 2, apr: 3, may: 4, jun: 5, jul: 6, aug: 7, sep: 8, oct: 9, nov: 10, dec: 11 };

const VALID_EVENT_TYPES = new Set(['CONNECTION', 'FAILED_LOGIN', 'TEST_LOGIN', 'DISCONNECT', 'PORT_PROBE', 'WEB_PROBE', 'SUSPICIOUS_REQUEST']);
const VALID_SEVERITIES = new Set(['LOW', 'MEDIUM', 'HIGH', 'CRITICAL', 'INFO']);

function sanitizeEventType(type) {
  if (!type) return 'CONNECTION';
  const upper = String(type).trim().toUpperCase().replace(/[-\s]/g, '_');
  if (VALID_EVENT_TYPES.has(upper)) return upper;
  if (upper.includes('FAIL') || upper.includes('INVALID') || upper.includes('AUTH') || upper.includes('REJECT') || upper.includes('DENY') || upper.includes('BRUTE') || upper.includes('BAD_PASS')) return 'FAILED_LOGIN';
  if (upper.includes('PORT') || upper.includes('SCAN') || upper.includes('PROBE')) return 'PORT_PROBE';
  if (upper.includes('WEB') || upper.includes('HTTP') || upper.includes('URL') || upper.includes('CGI')) return 'WEB_PROBE';
  if (upper.includes('DISCONNECT') || upper.includes('CLOSE') || upper.includes('BYE') || upper.includes('EXIT')) return 'DISCONNECT';
  if (upper.includes('ATTACK') || upper.includes('EXPLOIT') || upper.includes('SUSPICIOUS') || upper.includes('MALWARE')) return 'SUSPICIOUS_REQUEST';
  if (upper.includes('TEST') || upper.includes('SUCCESS') || upper.includes('ACCEPT')) return 'TEST_LOGIN';
  return 'CONNECTION';
}

function sanitizeSeverity(sev, eventType) {
  if (sev) {
    const s = String(sev).trim().toUpperCase();
    if (VALID_SEVERITIES.has(s)) return s;
    if (s.includes('CRIT') || s.includes('FATAL') || s.includes('EMERG')) return 'CRITICAL';
    if (s.includes('HIGH') || s.includes('ERR')) return 'HIGH';
    if (s.includes('MED') || s.includes('WARN')) return 'MEDIUM';
    if (s.includes('LOW') || s.includes('NOTE')) return 'LOW';
    if (s.includes('INFO') || s.includes('DEBUG')) return 'INFO';
  }
  if (eventType === 'SUSPICIOUS_REQUEST') return 'HIGH';
  if (eventType === 'FAILED_LOGIN' || eventType === 'PORT_PROBE' || eventType === 'WEB_PROBE') return 'MEDIUM';
  if (eventType === 'DISCONNECT') return 'LOW';
  return 'INFO';
}

function simpleHash(str) {
  let h = 0;
  for (let i = 0; i < str.length; i++) {
    h = ((h << 5) - h) + str.charCodeAt(i);
    h |= 0;
  }
  return Math.abs(h);
}

// Regex patterns
const RFC3164_RE = /^(?:<\d+>)?\s*([A-Za-z]{3})\s+(\d{1,2})\s+(\d{2}:\d{2}:\d{2})\s+(\S+)\s+([^:\[\s]+)(?:\[\d+\])?:\s*(.*)$/;
const ISO_SYSLOG_RE = /^(?:<\d+>)?(?:1\s+)?(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s+(\S+)\s+([^:\[\s]+)(?:\[\d+\])?:\s*(.*)$/;
const APACHE_LOG_RE = /^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+\S+\s+\S+\s+\[([^\]]+)\]\s+"([A-Z]+)\s+([^"\s]+)\s+[^"]*"\s+(\d+)/;
const FAILED_PW_RE = /failed password for (?:invalid user )?(\S+) from ([\d.]+) port (\d+)/i;
const ACCEPTED_PW_RE = /accepted password for (\S+) from ([\d.]+) port (\d+)/i;
const INVALID_USER_RE = /invalid user (\S+) from ([\d.]+)/i;
const CONNECT_RE = /(?:connection from|connected from|connection received from)\s+([\d.]+)(?:\s+port\s+(\d+))?/i;
const DISCONNECT_RE = /(?:connection closed|disconnected|received disconnect)\s+(?:by|from\s+)?([\d.]+)?/i;
const WEB_REQ_RE = /(?:GET|POST|HEAD|PUT|DELETE|OPTIONS)\s+(\/\S*)\s+HTTP/i;
const IP_RE = /\b(?:\d{1,3}\.){3}\d{1,3}\b/;

function parseSyslogDate(monthStr, dayStr, timeStr) {
  const now = new Date();
  const month = MONTHS[monthStr.toLowerCase()] ?? now.getMonth();
  const day = parseInt(dayStr, 10);
  const [h, m, s] = timeStr.split(':').map(Number);
  const date = new Date(now.getFullYear(), month, day, h || 0, m || 0, s || 0);
  if (date > new Date(now.getTime() + 86400000)) {
    date.setFullYear(now.getFullYear() - 1);
  }
  return date.toISOString();
}

function parseSyslogLine(line) {
  const cleanLine = line.trim();
  if (!cleanLine) return null;

  let ts = new Date().toISOString();
  let service = 'sshd';
  let msg = cleanLine;

  const mRfc = RFC3164_RE.exec(cleanLine);
  if (mRfc) {
    const [, month, day, time, , srv, message] = mRfc;
    ts = parseSyslogDate(month, day, time);
    service = srv;
    msg = message;
  } else {
    const mIso = ISO_SYSLOG_RE.exec(cleanLine);
    if (mIso) {
      const [, isoTime, , srv, message] = mIso;
      try { ts = new Date(isoTime).toISOString(); } catch (_) { ts = new Date().toISOString(); }
      service = srv;
      msg = message;
    }
  }

  // Check failed password
  const fm = FAILED_PW_RE.exec(msg);
  if (fm) {
    return {
      timestamp: ts,
      sourceIP: fm[2],
      sourcePort: parseInt(fm[3], 10) || 0,
      destinationPort: 22,
      service,
      protocol: 'TCP',
      eventType: 'FAILED_LOGIN',
      username: fm[1],
      status: 'failed',
      severity: 'MEDIUM',
      sessionId: 'SYS-' + (simpleHash(cleanLine) & 0xfffffff),
      metadata: { raw: cleanLine, logSource: 'syslog' }
    };
  }

  // Check invalid user
  const im = INVALID_USER_RE.exec(msg);
  if (im) {
    return {
      timestamp: ts,
      sourceIP: im[2],
      sourcePort: 0,
      destinationPort: 22,
      service,
      protocol: 'TCP',
      eventType: 'FAILED_LOGIN',
      username: im[1],
      status: 'failed',
      severity: 'MEDIUM',
      sessionId: 'SYS-' + (simpleHash(cleanLine) & 0xfffffff),
      metadata: { raw: cleanLine, logSource: 'syslog' }
    };
  }

  // Check accepted password
  const sm = ACCEPTED_PW_RE.exec(msg);
  if (sm) {
    return {
      timestamp: ts,
      sourceIP: sm[2],
      sourcePort: parseInt(sm[3], 10) || 0,
      destinationPort: 22,
      service,
      protocol: 'TCP',
      eventType: 'TEST_LOGIN',
      username: sm[1],
      status: 'success',
      severity: 'MEDIUM',
      sessionId: 'SYS-' + (simpleHash(cleanLine) & 0xfffffff),
      metadata: { raw: cleanLine, logSource: 'syslog' }
    };
  }

  // Check connect
  const cm = CONNECT_RE.exec(msg);
  if (cm) {
    return {
      timestamp: ts,
      sourceIP: cm[1],
      sourcePort: cm[2] ? parseInt(cm[2], 10) : 0,
      destinationPort: 22,
      service,
      protocol: 'TCP',
      eventType: 'CONNECTION',
      status: 'connected',
      severity: 'INFO',
      sessionId: 'SYS-' + (simpleHash(cleanLine) & 0xfffffff),
      metadata: { raw: cleanLine, logSource: 'syslog' }
    };
  }

  // Check disconnect
  const dm = DISCONNECT_RE.exec(msg);
  if (dm) {
    const sip = dm[1] || (msg.match(IP_RE)?.[0] || '127.0.0.1');
    return {
      timestamp: ts,
      sourceIP: sip,
      destinationPort: 22,
      service,
      protocol: 'TCP',
      eventType: 'DISCONNECT',
      status: 'disconnected',
      severity: 'LOW',
      sessionId: 'SYS-' + (simpleHash(cleanLine) & 0xfffffff),
      metadata: { raw: cleanLine, logSource: 'syslog' }
    };
  }

  // Check web request inside syslog or raw line
  const wm = WEB_REQ_RE.exec(msg);
  if (wm) {
    const path = wm[1];
    const suspicious = ['/admin', '/.env', '/wp-admin', '/config', '/backup', '/phpmyadmin', '/setup', '/actuator', '/etc'].some(p => path.toLowerCase().includes(p));
    const ipMatch = msg.match(IP_RE);
    const sip = ipMatch ? ipMatch[0] : '127.0.0.1';
    return {
      timestamp: ts,
      sourceIP: sip,
      destinationPort: 80,
      service: 'HTTP',
      protocol: 'TCP',
      eventType: suspicious ? 'WEB_PROBE' : 'CONNECTION',
      status: suspicious ? 'probed' : 'connected',
      severity: suspicious ? 'HIGH' : 'INFO',
      sessionId: 'SYS-' + (simpleHash(cleanLine) & 0xfffffff),
      metadata: { raw: cleanLine, path, logSource: 'syslog' }
    };
  }

  // Apache / Nginx format
  const am = APACHE_LOG_RE.exec(cleanLine);
  if (am) {
    const [, ip, , method, path, statusCode] = am;
    const suspicious = parseInt(statusCode, 10) === 404 || parseInt(statusCode, 10) === 403 ||
      ['/admin', '/.env', '/wp-admin', '/config', '/phpmyadmin', '/shell', '/api'].some(p => path.toLowerCase().includes(p));
    return {
      timestamp: ts,
      sourceIP: ip,
      destinationPort: 80,
      service: 'HTTP',
      protocol: 'TCP',
      eventType: suspicious ? 'WEB_PROBE' : 'CONNECTION',
      status: suspicious ? 'probed' : 'connected',
      severity: suspicious ? 'HIGH' : 'INFO',
      sessionId: 'WEB-' + (simpleHash(cleanLine) & 0xfffffff),
      metadata: { raw: cleanLine, method, path, statusCode, logSource: 'web' }
    };
  }

  // Key=Value format (Firewall / iptables / Fortinet / ufw / Suricata / Palo Alto logs)
  if (cleanLine.includes('=') && (cleanLine.includes('SRC=') || cleanLine.includes('src=') || cleanLine.includes('ip=') || cleanLine.includes('from='))) {
    const kvMatch = (key) => {
      const m = new RegExp(`(?:^|[\\s,;])${key}=([\\S]+)`, 'i').exec(cleanLine);
      return m ? m[1].replace(/['"]/g, '') : null;
    };
    const src = kvMatch('src') || kvMatch('source') || kvMatch('src_ip') || kvMatch('ip') || kvMatch('from') || cleanLine.match(IP_RE)?.[0];
    const dst = kvMatch('dst') || kvMatch('destination') || kvMatch('dst_ip') || kvMatch('to') || '127.0.0.1';
    const spt = parseInt(kvMatch('spt') || kvMatch('sport') || kvMatch('src_port') || '0', 10);
    const dpt = parseInt(kvMatch('dpt') || kvMatch('dport') || kvMatch('dst_port') || '22', 10);
    const proto = (kvMatch('proto') || kvMatch('protocol') || 'TCP').toUpperCase();
    const action = (kvMatch('action') || kvMatch('status') || kvMatch('msg') || '').toLowerCase();
    const isDrop = action.includes('drop') || action.includes('block') || action.includes('deny') || action.includes('reject');

    if (src) {
      return {
        timestamp: ts,
        sourceIP: src,
        sourcePort: isNaN(spt) ? undefined : spt,
        destinationIP: dst,
        destinationPort: isNaN(dpt) ? 22 : dpt,
        service: dpt === 80 || dpt === 8080 || dpt === 443 ? 'HTTP' : (dpt === 22 ? 'SSH' : 'TCP'),
        protocol: proto,
        eventType: isDrop ? 'PORT_PROBE' : 'CONNECTION',
        status: isDrop ? 'probed' : 'connected',
        severity: isDrop ? 'MEDIUM' : 'INFO',
        sessionId: 'KV-' + (simpleHash(cleanLine) & 0xfffffff),
        metadata: { raw: cleanLine, logSource: 'kv' }
      };
    }
  }

  // Fallback 1: If line contains an IP address, extract it as an event
  const ipMatch = cleanLine.match(IP_RE);
  if (ipMatch) {
    const sip = ipMatch[0];
    const lower = cleanLine.toLowerCase();
    let evType = 'CONNECTION';
    let sev = 'INFO';
    let srv = 'SSH';
    let status = 'connected';

    if (lower.includes('fail') || lower.includes('invalid') || lower.includes('denied') || lower.includes('reject') || lower.includes('bad password')) {
      evType = 'FAILED_LOGIN';
      sev = 'MEDIUM';
      status = 'failed';
    } else if (lower.includes('probe') || lower.includes('scan') || lower.includes('nmap')) {
      evType = 'PORT_PROBE';
      sev = 'MEDIUM';
      status = 'probed';
    } else if (lower.includes('get ') || lower.includes('post ') || lower.includes('http') || lower.includes('url')) {
      evType = 'WEB_PROBE';
      sev = 'MEDIUM';
      status = 'probed';
      srv = 'HTTP';
    } else if (lower.includes('disconnect') || lower.includes('closed') || lower.includes('exit')) {
      evType = 'DISCONNECT';
      sev = 'LOW';
      status = 'disconnected';
    }

    if (lower.includes('http') || lower.includes('nginx') || lower.includes('apache')) srv = 'HTTP';
    if (lower.includes('ftp')) srv = 'FTP';
    if (lower.includes('telnet')) srv = 'TELNET';

    return {
      timestamp: ts,
      sourceIP: sip,
      destinationPort: srv === 'HTTP' ? 80 : 22,
      service: srv,
      protocol: 'TCP',
      eventType: evType,
      status,
      severity: sev,
      sessionId: 'LOG-' + (simpleHash(cleanLine) & 0xfffffff),
      metadata: { raw: cleanLine, logSource: 'generic' }
    };
  }

  // Fallback 2: Recognizable security keywords even without explicit IP
  const lower = cleanLine.toLowerCase();
  if (lower.includes('fail') || lower.includes('invalid user') || lower.includes('attack') || lower.includes('probe') || lower.includes('unauthorized') || lower.includes('brute force')) {
    const isFail = lower.includes('fail') || lower.includes('invalid') || lower.includes('unauth');
    const isProbe = lower.includes('probe') || lower.includes('scan');
    return {
      timestamp: ts,
      sourceIP: '127.0.0.1',
      destinationPort: 22,
      service: lower.includes('http') || lower.includes('web') ? 'HTTP' : 'SSH',
      protocol: 'TCP',
      eventType: isFail ? 'FAILED_LOGIN' : (isProbe ? 'PORT_PROBE' : 'SUSPICIOUS_REQUEST'),
      status: isFail ? 'failed' : 'probed',
      severity: isFail || isProbe ? 'MEDIUM' : 'HIGH',
      sessionId: 'GEN-' + (simpleHash(cleanLine) & 0xfffffff),
      metadata: { raw: cleanLine, logSource: 'generic' }
    };
  }

  return null;
}

function parseCsv(text) {
  const rows = [];
  const lines = text.split(/\r?\n/).filter(l => l.trim());
  if (lines.length === 0) return rows;

  // Determine delimiter
  const first = lines[0];
  const delim = first.includes('\t') ? '\t' : (first.includes(';') ? ';' : ',');

  const rawHeaders = first.split(delim).map(h => h.trim().replace(/^["']|["']$/g, ''));
  const normHeaders = rawHeaders.map(h => h.toLowerCase().replace(/[^a-z0-9]/g, ''));

  function findCol(exactList, subList = []) {
    for (const key of exactList) {
      const idx = normHeaders.indexOf(key);
      if (idx >= 0) return idx;
    }
    for (const sub of subList) {
      const idx = normHeaders.findIndex(h => h.includes(sub));
      if (idx >= 0) return idx;
    }
    return -1;
  }

  const ipIdx = findCol(['sourceip', 'srcip', 'source', 'clientip', 'attackerip', 'src', 'attacker'], ['sourceip', 'srcip', 'clientip', 'ip']);
  const destIpIdx = findCol(['destinationip', 'dstip', 'targetip', 'serverip', 'destip', 'dst', 'target']);
  const timeIdx = findCol(['timestamp', 'time', 'date', 'datetime', 'loggedat', 'createdat', 'logtime']);
  const eventIdx = findCol(['eventtype', 'event', 'type', 'action', 'activity', 'attacktype']);
  const serviceIdx = findCol(['service', 'app', 'protocolservice', 'application']);
  const protoIdx = findCol(['protocol', 'proto']);
  const userIdx = findCol(['username', 'user', 'account', 'login', 'srcuser']);
  const statusIdx = findCol(['status', 'outcome', 'result', 'state', 'actionresult']);
  const sevIdx = findCol(['severity', 'level', 'priority', 'threatlevel']);
  const sportIdx = findCol(['sourceport', 'srcport', 'sport', 'source_port']);
  let dportIdx = findCol(['destinationport', 'dstport', 'dport', 'destport']);
  if (dportIdx === -1) {
    const genericPortIdx = normHeaders.indexOf('port');
    if (genericPortIdx >= 0 && genericPortIdx !== sportIdx) dportIdx = genericPortIdx;
  }

  const isHeader = ipIdx >= 0 || timeIdx >= 0 || eventIdx >= 0 || normHeaders.includes('timestamp') || normHeaders.includes('eventtype') || normHeaders.includes('sourceip');
  const startLine = isHeader ? 1 : 0;

  for (let i = startLine; i < lines.length; i++) {
    const line = lines[i];
    if (!line.trim()) continue;
    const vals = line.split(delim).map(v => v.trim().replace(/^["']|["']$/g, ''));
    if (!vals.length || (vals.length === 1 && !vals[0])) continue;

    const sip = (ipIdx >= 0 && vals[ipIdx] ? vals[ipIdx] : '') || line.match(IP_RE)?.[0] || '127.0.0.1';
    const dip = (destIpIdx >= 0 && vals[destIpIdx] ? vals[destIpIdx] : '') || '127.0.0.1';
    let ts = (timeIdx >= 0 && vals[timeIdx] ? vals[timeIdx] : '') || new Date().toISOString();
    try {
      const d = new Date(ts);
      ts = isNaN(d.getTime()) ? new Date().toISOString() : d.toISOString();
    } catch (_) { ts = new Date().toISOString(); }

    const rawEvType = eventIdx >= 0 && vals[eventIdx] ? vals[eventIdx] : '';
    const rawSev = sevIdx >= 0 && vals[sevIdx] ? vals[sevIdx] : '';
    const evType = sanitizeEventType(rawEvType || 'CONNECTION');
    const sev = sanitizeSeverity(rawSev, evType);
    const service = (serviceIdx >= 0 && vals[serviceIdx] ? vals[serviceIdx] : '') || (evType === 'WEB_PROBE' ? 'HTTP' : 'SSH');
    const status = (statusIdx >= 0 && vals[statusIdx] ? vals[statusIdx] : '') || (evType === 'FAILED_LOGIN' ? 'failed' : 'connected');

    const sp = sportIdx >= 0 ? parseInt(vals[sportIdx], 10) : undefined;
    const dp = dportIdx >= 0 ? parseInt(vals[dportIdx], 10) : (service === 'HTTP' ? 80 : 22);

    rows.push({
      timestamp: ts,
      sourceIP: sip,
      sourcePort: isNaN(sp) ? undefined : sp,
      destinationIP: dip,
      destinationPort: isNaN(dp) ? (service === 'HTTP' ? 80 : 22) : dp,
      service,
      protocol: (protoIdx >= 0 && vals[protoIdx] ? vals[protoIdx] : '') || 'TCP',
      eventType: evType,
      username: userIdx >= 0 && vals[userIdx] ? vals[userIdx] : undefined,
      status,
      severity: sev,
      sessionId: 'CSV-' + (simpleHash(line) & 0xfffffff),
      metadata: { raw: line, logSource: 'csv' }
    });
  }

  return rows;
}

function normalizeJsonEvent(obj) {
  if (!obj || typeof obj !== 'object') return null;
  // If wrapped in _source (Elasticsearch) or event (Suricata/ECS)
  if (obj._source && typeof obj._source === 'object') obj = { ...obj, ...obj._source };
  if (obj.event && typeof obj.event === 'object') obj = { ...obj, ...obj.event };

  const sip = obj.sourceIP || obj.src_ip || obj.source_ip || obj.ip || obj.client_ip || obj.clientIp || obj.host || obj.src || obj.attacker || '127.0.0.1';
  const dip = obj.destinationIP || obj.dst_ip || obj.dest_ip || obj.target_ip || obj.dst || obj.destination || '127.0.0.1';

  let rawTs = obj.timestamp || obj.time || obj.date || obj['@timestamp'] || obj.logTime || obj.created_at || new Date().toISOString();
  let ts = new Date().toISOString();
  try {
    const d = new Date(rawTs);
    ts = isNaN(d.getTime()) ? new Date().toISOString() : d.toISOString();
  } catch (_) { ts = new Date().toISOString(); }

  const rawEvType = obj.eventType || obj.event_type || obj.type || obj.action || obj.eventid || obj.event_id || obj.name || (obj.alert ? obj.alert.signature : '');
  const evType = sanitizeEventType(rawEvType || 'CONNECTION');

  const rawSev = obj.severity || obj.level || obj.priority || (obj.alert ? obj.alert.severity : '');
  const sev = sanitizeSeverity(rawSev, evType);

  const sp = obj.sourcePort != null ? Number(obj.sourcePort) : (obj.src_port != null ? Number(obj.src_port) : (obj.sport != null ? Number(obj.sport) : undefined));
  const dp = obj.destinationPort != null ? Number(obj.destinationPort) : (obj.dst_port != null ? Number(obj.dst_port) : (obj.dport != null ? Number(obj.dport) : (evType === 'WEB_PROBE' ? 80 : 22)));

  const service = obj.service || (obj.proto === 'http' || dp === 80 || dp === 8080 || dp === 443 ? 'HTTP' : (dp === 22 || dp === 2222 ? 'SSH' : 'TCP'));

  return {
    ...obj,
    timestamp: ts,
    sourceIP: String(sip),
    destinationIP: String(dip),
    sourcePort: isNaN(sp) ? undefined : sp,
    destinationPort: isNaN(dp) ? (service === 'HTTP' ? 80 : 22) : dp,
    service,
    protocol: obj.protocol || obj.proto || 'TCP',
    eventType: evType,
    username: obj.username || obj.user || obj.account || obj.login,
    passwordEcho: obj.passwordEcho || (obj.password ? `len=${String(obj.password).length} sha-prefix=***` : undefined),
    status: obj.status || (evType === 'FAILED_LOGIN' ? 'failed' : 'connected'),
    severity: sev,
    sessionId: obj.sessionId || ('JSON-' + (simpleHash(JSON.stringify(obj)) & 0xfffffff)),
    metadata: { ...(obj.metadata || {}), logSource: 'json' }
  };
}

function parseJson(text) {
  const trimmed = text.trim();
  // 1. Try full JSON parse
  try {
    const parsed = JSON.parse(trimmed);
    if (Array.isArray(parsed)) {
      return parsed.map(normalizeJsonEvent).filter(Boolean);
    }
    if (parsed && typeof parsed === 'object') {
      const arrayKeys = ['events', 'logs', 'data', 'records', 'items', 'results', 'hits', 'logEvents'];
      for (const k of arrayKeys) {
        if (Array.isArray(parsed[k])) return parsed[k].map(normalizeJsonEvent).filter(Boolean);
      }
      if (parsed.hits && Array.isArray(parsed.hits.hits)) {
        return parsed.hits.hits.map(normalizeJsonEvent).filter(Boolean);
      }
      const ev = normalizeJsonEvent(parsed);
      return ev ? [ev] : [];
    }
  } catch (_) {}

  // 2. Try JSON lines (NDJSON)
  const rows = [];
  for (const line of trimmed.split(/\r?\n/)) {
    const l = line.trim();
    if (!l) continue;
    try {
      const obj = JSON.parse(l);
      const ev = normalizeJsonEvent(obj);
      if (ev) rows.push(ev);
    } catch (_) {}
  }
  return rows;
}

function parsePcap(buffer) {
  if (!buffer || buffer.length < 24) return [];
  const magic = buffer.readUInt32LE(0);
  let isLe = true;
  if (magic === 0xa1b2c3d4) isLe = true;
  else if (magic === 0xd4c3b2a1) isLe = false;
  else return [];

  const events = [];
  let offset = 24;
  while (offset + 16 <= buffer.length && events.length < 500) {
    const tsSec = isLe ? buffer.readUInt32LE(offset) : buffer.readUInt32BE(offset);
    const inclLen = isLe ? buffer.readUInt32LE(offset + 8) : buffer.readUInt32BE(offset + 8);
    offset += 16;
    if (offset + inclLen > buffer.length) break;

    const pkt = buffer.subarray(offset, offset + inclLen);
    offset += inclLen;

    // Check Ethernet IPv4 (EtherType 0x0800 at offset 12)
    if (pkt.length >= 34 && pkt[12] === 0x08 && pkt[13] === 0x00) {
      const ipOffset = 14;
      const proto = pkt[ipOffset + 9]; // 6=TCP, 17=UDP
      const srcIP = `${pkt[ipOffset + 12]}.${pkt[ipOffset + 13]}.${pkt[ipOffset + 14]}.${pkt[ipOffset + 15]}`;
      const dstIP = `${pkt[ipOffset + 16]}.${pkt[ipOffset + 17]}.${pkt[ipOffset + 18]}.${pkt[ipOffset + 19]}`;
      const ihl = (pkt[ipOffset] & 0x0f) * 4;
      const transOffset = ipOffset + ihl;

      if (pkt.length >= transOffset + 4) {
        const sport = (pkt[transOffset] << 8) | pkt[transOffset + 1];
        const dport = (pkt[transOffset + 2] << 8) | pkt[transOffset + 3];
        const srv = dport === 80 || dport === 8080 || dport === 443 ? 'HTTP' : (dport === 22 || dport === 2222 ? 'SSH' : 'TCP');
        events.push({
          timestamp: new Date(tsSec * 1000).toISOString(),
          sourceIP: srcIP,
          sourcePort: sport,
          destinationIP: dstIP,
          destinationPort: dport,
          service: srv,
          protocol: proto === 6 ? 'TCP' : (proto === 17 ? 'UDP' : 'IP'),
          eventType: 'CONNECTION',
          status: 'connected',
          severity: 'INFO',
          sessionId: `PCAP-${events.length}`,
          metadata: { logSource: 'pcap', packetSize: inclLen }
        });
      }
    }
  }
  return events;
}

function parse(textOrBuffer) {
  if (!textOrBuffer) return [];

  // Buffer check for PCAP
  if (Buffer.isBuffer(textOrBuffer)) {
    if (textOrBuffer.length >= 4) {
      const magic = textOrBuffer.readUInt32LE(0);
      if (magic === 0xa1b2c3d4 || magic === 0xd4c3b2a1) {
        return parsePcap(textOrBuffer);
      }
    }
    textOrBuffer = textOrBuffer.toString('utf8');
  }

  if (typeof textOrBuffer !== 'string') return [];
  // Strip UTF-8 BOM if present
  let trimmed = textOrBuffer.replace(/^\uFEFF/, '').trim();
  if (!trimmed) return [];

  // 1. Check if it's JSON
  if (trimmed.startsWith('[') || trimmed.startsWith('{')) {
    const jsonEvents = parseJson(trimmed);
    if (jsonEvents.length > 0) return jsonEvents;
  }

  // 2. Check if it's CSV / TSV
  const firstLine = trimmed.split(/\r?\n/)[0] || '';
  const firstLower = firstLine.toLowerCase();
  const isDelimited = firstLine.includes(',') || firstLine.includes('\t') || firstLine.includes(';');
  const hasCsvHeaders = isDelimited && (
    firstLower.includes('ip') || firstLower.includes('source') || firstLower.includes('time') ||
    firstLower.includes('date') || firstLower.includes('event') || firstLower.includes('user') ||
    firstLower.includes('service') || firstLower.includes('port')
  );

  if (hasCsvHeaders) {
    const csvEvents = parseCsv(trimmed);
    if (csvEvents.length > 0) return csvEvents;
  }

  // 3. Line by line parsing for Syslog, Apache, Cowrie, or text logs
  const lines = trimmed.split(/\r?\n/);
  const events = [];
  for (const line of lines) {
    const ev = parseSyslogLine(line);
    if (ev) events.push(ev);
  }
  if (events.length > 0) return events;

  // 4. Try JSON lines
  const jsonLines = parseJson(trimmed);
  if (jsonLines.length > 0) return jsonLines;

  // 5. If comma delimited, attempt raw CSV without headers
  if (isDelimited) {
    const fallbackCsv = parseCsv(trimmed);
    if (fallbackCsv.length > 0) return fallbackCsv;
  }

  return [];
}

module.exports = { parse, parseSyslogLine, parseCsv, parseJson, parsePcap, sanitizeEventType, sanitizeSeverity };
